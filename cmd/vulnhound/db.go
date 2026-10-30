package main

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/0x48core/vulnhound/internal/osvdb"
)

func newDBCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Manage the offline vulnerability database",
		Long: `vulnhound normally queries the OSV.dev API. With a local copy of the OSV
database, scans can run with --offline: no network, and faster.

The database lives in $VULNHOUND_DB_DIR, or in vulnhound/osv under your
user cache directory.`,
	}
	cmd.AddCommand(newDBUpdateCmd(), newDBStatusCmd())
	return cmd
}

func newDBUpdateCmd() *cobra.Command {
	var (
		all bool
		url string
	)
	cmd := &cobra.Command{
		Use:   "update [ECOSYSTEM...]",
		Short: "Download or refresh the offline database",
		Long: `Download the OSV dump for each ecosystem, or refresh it if it changed.

Ecosystems: ` + strings.Join(osvdb.Ecosystems, ", ") + `.
Without arguments, the installed ecosystems are refreshed; on first use
` + strings.Join(osvdb.DefaultEcosystems, ", ") + ` are downloaded (about 300 MB).
Ubuntu (about 770 MB) is only downloaded when named or with --all.`,
		Example: `  vulnhound db update
  vulnhound db update Go npm
  vulnhound db update Ubuntu`,
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			defer func() { _ = db.Close() }()
			if url != "" {
				db.BaseURL = url
			}

			ecosystems, err := ecosystemsToUpdate(db, args, all)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			var failed []error
			for _, eco := range ecosystems {
				start := time.Now()
				fmt.Fprintf(out, "%-7s ", eco)
				res, err := db.Update(cmd.Context(), eco)
				switch {
				case err != nil:
					fmt.Fprintln(out, "failed")
					failed = append(failed, err)
				case res.Changed:
					fmt.Fprintf(out, "updated: %s, %d advisories (%s)\n",
						humanSize(res.Meta.Size), res.Meta.Records, time.Since(start).Round(100*time.Millisecond))
				default:
					fmt.Fprintln(out, "up to date")
				}
			}
			fmt.Fprintf(out, "Database: %s\n", db.Dir)
			return errors.Join(failed...)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "update every supported ecosystem, including Ubuntu")
	cmd.Flags().StringVar(&url, "url", "", "base URL of the OSV dumps")
	_ = cmd.Flags().MarkHidden("url")
	return cmd
}

func newDBStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show what the offline database contains",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			db, err := openDB()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			metas := db.Status()
			if len(metas) == 0 {
				fmt.Fprintf(out, "No offline database in %s.\nRun `vulnhound db update` to download one.\n", db.Dir)
				return nil
			}
			now := time.Now()
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ECOSYSTEM\tUPDATED\tSIZE\tADVISORIES")
			for _, m := range metas {
				updated := m.UpdatedAt.Local().Format("2006-01-02 15:04")
				if m.Stale(now) {
					updated += " (stale)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", m.Ecosystem, updated, humanSize(m.Size), m.Records)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			fmt.Fprintf(out, "\nDatabase: %s\n", db.Dir)
			return nil
		},
	}
}

func openDB() (*osvdb.DB, error) {
	dir, err := osvdb.DefaultDir()
	if err != nil {
		return nil, fmt.Errorf("locate offline database: %w", err)
	}
	return osvdb.New(dir), nil
}

// ecosystemsToUpdate resolves the arguments of `db update`. Names are
// case-insensitive.
func ecosystemsToUpdate(db *osvdb.DB, args []string, all bool) ([]string, error) {
	if all {
		return osvdb.Ecosystems, nil
	}
	if len(args) == 0 {
		var installed []string
		for _, m := range db.Status() {
			installed = append(installed, m.Ecosystem)
		}
		if len(installed) > 0 {
			return installed, nil
		}
		return osvdb.DefaultEcosystems, nil
	}
	var out []string
	for _, a := range args {
		found := ""
		for _, e := range osvdb.Ecosystems {
			if strings.EqualFold(a, e) {
				found = e
			}
		}
		if found == "" {
			return nil, fmt.Errorf("unknown ecosystem %q (supported: %s)", a, strings.Join(osvdb.Ecosystems, ", "))
		}
		out = append(out, found)
	}
	return out, nil
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
