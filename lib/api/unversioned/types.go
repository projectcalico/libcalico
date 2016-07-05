package unversioned

// All resources (and resource lists) implement the Resource interface.
type Resource interface {
	GetTypeMetadata() TypeMetadata
	SetKind(string)
	SetAPIVersion(string)
}

// ---- Type metadata ----
//
type TypeMetadata struct {
	Kind       string `json:"kind" validate:"required"`
	APIVersion string `json:"apiVersion" validate:"required"`
}

func (md TypeMetadata) GetTypeMetadata() TypeMetadata {
	return md
}

func (md TypeMetadata) SetKind(kind string) {
	md.Kind = kind
}

func (md TypeMetadata) SetAPIVersion(apiVersion string) {
	md.APIVersion = apiVersion
}

// ---- Metadata common to all resources ----
type ObjectMetadata struct {
	Name string `json:"name,omitempty" validate:"omitempty,name"`
}

// ---- Metadata common to all lists ----
type ListMetadata struct {
}
