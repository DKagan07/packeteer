package enrich

type Provider interface {
	Lookup(string)
}
