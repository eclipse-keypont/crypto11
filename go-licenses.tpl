# Third-Party Notices

This project uses the following third-party Go modules.

| Package | License | License URL |
|---------|---------|-------------|
{{- range .}}
| `{{.Name}}` | {{.LicenseName}} | {{if and .LicenseURL (ne .LicenseURL "Unknown")}}[Link]({{.LicenseURL}}){{else}}N/A{{end}} |
{{- end}}
