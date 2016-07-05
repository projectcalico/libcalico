package common

import (
	"reflect"
	"regexp"

	"github.com/golang/glog"
	"github.com/projectcalico/libcalico/lib/selector"
	"gopkg.in/go-playground/validator.v8"
)

var validate *validator.Validate

var (
	nameRegex          = regexp.MustCompile("^[a-zA-Z0-9_.-]+$")
	actionRegex        = regexp.MustCompile("^(nextTier|allow|deny)$")
	backendActionRegex = regexp.MustCompile("^(next-tier|allow|deny)$")
	protocolRegex      = regexp.MustCompile("^(tcp|udp|icmp|icmpv6|sctp|udplite)$")
)

func init() {
	// Initialise static data.
	config := &validator.Config{TagName: "validate", FieldNameTag: "json"}
	validate = validator.New(config)

	// Register some common validators.
	RegisterFieldValidator("action", validateAction)
	RegisterFieldValidator("backendaction", validateBackendAction)
	RegisterFieldValidator("name", validateName)
	RegisterFieldValidator("selector", validateSelector)
	RegisterFieldValidator("tag", validateTag)
	RegisterFieldValidator("labels", validateLabels)
	RegisterFieldValidator("interface", validateInterface)

	RegisterStructValidator(validateProtocol, Protocol{})
}

func RegisterFieldValidator(key string, fn validator.Func) {
	validate.RegisterValidation(key, fn)
}

func RegisterStructValidator(fn validator.StructLevelFunc, t ...interface{}) {
	validate.RegisterStructValidation(fn, t...)
}

func Validate(current interface{}) error {
	err := validate.Struct(current)
	if err == nil {
		return nil
	}

	verr := ErrorValidation{}
	for _, f := range err.(validator.ValidationErrors) {
		verr.ErrFields = append(verr.ErrFields,
			ErroredField{Name: f.Name, Value: f.Value})
	}
	return verr
}

func validateAction(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	glog.V(2).Infof("Validate action: %s\n", s)
	return actionRegex.MatchString(s)
}

func validateBackendAction(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	glog.V(2).Infof("Validate action: %s\n", s)
	return backendActionRegex.MatchString(s)
}

func validateName(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	glog.V(2).Infof("Validate name: %s\n", s)
	return nameRegex.MatchString(s)
}

func validateSelector(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	glog.V(2).Infof("Validate selector: %s\n", s)
	_, err := selector.Parse(s)
	if err != nil {
		glog.Errorf("Selector %#v was invalid: %v", s, err)
		return false
	}
	return true
}

func validateTag(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	s := field.String()
	glog.V(2).Infof("Validate tag: %s\n", s)
	return nameRegex.MatchString(s)
}

func validateLabels(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	l := field.Interface().(map[string]string)
	glog.V(2).Infof("Validate labels: %s\n", l)
	for k, v := range l {
		if !nameRegex.MatchString(k) || !nameRegex.MatchString(v) {
			return false
		}
	}
	return true
}

func validateInterface(v *validator.Validate, topStruct reflect.Value, currentStructOrField reflect.Value, field reflect.Value, fieldType reflect.Type, fieldKind reflect.Kind, param string) bool {
	b := []byte(field.String())
	glog.V(2).Infof("Validate interface: %s\n", b)
	return nameRegex.Match(b)
}

func validateProtocol(v *validator.Validate, structLevel *validator.StructLevel) {
	glog.V(2).Infof("Validate protocol")
	p := structLevel.CurrentStruct.Interface().(Protocol)
	glog.V(2).Infof("Validate protocol: %v %s %v\n", p.Type, p.StrVal, p.NumVal)
	if p.Type == NumOrStringNum && ((p.NumVal < 1) || (p.NumVal > 255)) {
		structLevel.ReportError(reflect.ValueOf(p.NumVal), "Protocol", "protocol", "protocol number invalid")
	} else if p.Type == NumOrStringString && !protocolRegex.MatchString(p.StrVal) {
		structLevel.ReportError(reflect.ValueOf(p.StrVal), "Protocol", "protocol", "protocol name invalid")
	}
}
