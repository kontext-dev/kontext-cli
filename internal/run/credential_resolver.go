package run

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/cli/browser"

	"github.com/kontext-security/kontext-cli/internal/auth"
	"github.com/kontext-security/kontext-cli/internal/credential"
)

type credentialResolverSet struct {
	kontext *kontextCredentialResolver
}

func newCredentialResolverSet(
	session *auth.Session,
	credentialClientID string,
) *credentialResolverSet {
	return newCredentialResolverSetWithFetcher(session, credentialClientID, fetchConnectURLForConnectFlow)
}

func newCredentialResolverSetWithFetcher(
	session *auth.Session,
	credentialClientID string,
	fetchConnect connectURLFetcher,
) *credentialResolverSet {
	return &credentialResolverSet{
		kontext: &kontextCredentialResolver{
			session:            session,
			credentialClientID: credentialClientID,
			fetchConnectURL:    fetchConnect,
		},
	}
}

func (s *credentialResolverSet) resolve(
	ctx context.Context,
	entry credential.Entry,
) (string, error) {
	return s.kontext.Resolve(ctx, entry)
}

func (s *credentialResolverSet) unresolvedConnectableEntries(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) []credential.Entry {
	return s.kontext.UnresolvedConnectableEntries(entryByEnvVar, failures)
}

func (s *credentialResolverSet) connectAndRetry(
	ctx context.Context,
	entries []credential.Entry,
) ([]credential.Resolved, map[string]error) {
	return s.kontext.ConnectAndRetry(ctx, entries)
}

func (s *credentialResolverSet) printLaunchWarnings(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) {
	s.kontext.PrintLaunchWarnings(entryByEnvVar, failures)
}

type kontextCredentialResolver struct {
	session            *auth.Session
	credentialClientID string
	fetchConnectURL    connectURLFetcher
}

func (r *kontextCredentialResolver) Resolve(
	ctx context.Context,
	entry credential.Entry,
) (string, error) {
	return exchangeCredential(ctx, r.session, entry, r.credentialClientID)
}

func (r *kontextCredentialResolver) UnresolvedConnectableEntries(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) []credential.Entry {
	var entries []credential.Entry
	for envVar, err := range failures {
		resolutionErr, ok := err.(*credentialResolutionError)
		if !ok || resolutionErr.Reason != failureDisconnected {
			continue
		}
		entry, ok := entryByEnvVar[envVar]
		if !ok {
			continue
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b credential.Entry) int {
		return strings.Compare(a.EnvVar, b.EnvVar)
	})
	return entries
}

func (r *kontextCredentialResolver) ConnectAndRetry(
	ctx context.Context,
	entries []credential.Entry,
) ([]credential.Resolved, map[string]error) {
	interactive := isInteractiveTerminal()
	connectURL, connectErr := r.fetchConnectURL(
		ctx,
		r.session,
		r.credentialClientID,
		interactive,
		auth.Login,
	)
	if connectErr != nil {
		if !interactive && needsGatewayAccessReauthentication(connectErr) {
			fmt.Fprintln(os.Stderr, "⚠ Non-interactive session detected. Re-run `kontext start` in an interactive terminal to authorize hosted connect.")
		}
		fmt.Fprintf(os.Stderr, "⚠ Could not create hosted connect session (%v)\n", connectErr)
		return nil, failureMap(entries, connectErr)
	}

	providerList := joinEntryProviders(entries)
	fmt.Fprintf(os.Stderr, "\nHosted connect is available for: %s\n", providerList)
	fmt.Fprintf(os.Stderr, "  %s\n", connectURL)

	if !interactive {
		fmt.Fprintln(os.Stderr, "⚠ Non-interactive session detected. Open this URL in a browser, then rerun `kontext start`.")
		return nil, failureMap(entries, fmt.Errorf("hosted connect requires browser completion"))
	}

	fmt.Fprintf(os.Stderr, "  Opening browser to connect %s...\n", providerList)
	if err := browser.OpenURL(connectURL); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠ Could not open browser automatically (%v)\n", err)
		fmt.Fprintln(os.Stderr, "  Open the URL above to continue.")
	}
	fmt.Fprint(os.Stderr, "  Press Enter after connecting...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	return r.retryEntries(ctx, entries)
}

func (r *kontextCredentialResolver) retryEntries(
	ctx context.Context,
	entries []credential.Entry,
) ([]credential.Resolved, map[string]error) {
	attemptDelays := []time.Duration{0, 3 * time.Second, 7 * time.Second}
	pending := make(map[string]credential.Entry, len(entries))
	for _, entry := range entries {
		pending[entry.EnvVar] = entry
	}
	failures := make(map[string]error, len(entries))
	resolved := make([]credential.Resolved, 0, len(entries))

	for attempt, delay := range attemptDelays {
		if len(pending) == 0 {
			break
		}
		if delay > 0 {
			time.Sleep(delay)
		}

		for envVar, entry := range pending {
			fmt.Fprintf(
				os.Stderr,
				"  Retrying %s (%d/%d)... ",
				entry.EnvVar,
				attempt+1,
				len(attemptDelays),
			)
			value, err := r.Resolve(ctx, entry)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠ skipped (%v)\n", err)
				failures[envVar] = err
				continue
			}
			fmt.Fprintln(os.Stderr, "✓")
			resolved = append(resolved, credential.Resolved{Entry: entry, Value: value})
			delete(failures, envVar)
			delete(pending, envVar)
		}
	}

	return resolved, failures
}

func (r *kontextCredentialResolver) PrintLaunchWarnings(
	entryByEnvVar map[string]credential.Entry,
	failures map[string]error,
) {
	if len(failures) == 0 {
		return
	}

	var skipped []string
	for envVar, err := range failures {
		entry, ok := entryByEnvVar[envVar]
		if !ok {
			continue
		}
		if resolutionErr, ok := err.(*credentialResolutionError); ok {
			switch resolutionErr.Reason {
			case failureNotAttached:
				fmt.Fprintf(
					os.Stderr,
					"⚠ %s is not attached to the Kontext CLI application. Attach %s to kontext-cli in the dashboard or edit %s.\n",
					entry.Provider,
					entry.Provider,
					entry.EnvVar,
				)
			case failureUnknown:
				fmt.Fprintf(os.Stderr, "⚠ %s references an unknown provider handle.\n", entry.EnvVar)
			case failureTransient:
				fmt.Fprintf(os.Stderr, "⚠ %s could not be resolved because of a temporary exchange error.\n", entry.EnvVar)
			case failureInvalid:
				fmt.Fprintf(os.Stderr, "⚠ %s contains an invalid Kontext placeholder.\n", entry.EnvVar)
			case failureDisconnected:
				fmt.Fprintf(
					os.Stderr,
					"⚠ %s was not available for this launch. Connect it in hosted connect and rerun `kontext start`.\n",
					entry.EnvVar,
				)
				skipped = append(skipped, entry.Provider)
			default:
				fmt.Fprintf(os.Stderr, "⚠ %s was skipped (%v)\n", entry.EnvVar, err)
			}
			continue
		}

		fmt.Fprintf(os.Stderr, "⚠ %s was skipped (%v)\n", entry.EnvVar, err)
	}

	if len(skipped) > 0 {
		slices.Sort(skipped)
		fmt.Fprintf(os.Stderr, "⚠ Launching without these providers: %s\n", strings.Join(slices.Compact(skipped), ", "))
		fmt.Fprintln(os.Stderr, "⚠ Providers connected after launch become available on the next `kontext start`.")
	}
}

func failureMap(entries []credential.Entry, err error) map[string]error {
	failures := make(map[string]error, len(entries))
	for _, entry := range entries {
		failures[entry.EnvVar] = err
	}
	return failures
}
