package matrixfederation

import (
	"encoding/json"
	"testing"
)

func TestMarshalBase64(t *testing.T) {
	input := Base64String("this\xffis\xffa\xfftest")
	want := `"dGhpc/9pc/9h/3Rlc3Q"`
	got, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("json.Marshal(Base64String(%q)): wanted %q got %q", string(input), want, string(got))
	}
}

func TestUnmarshalBase64(t *testing.T) {
	input := []byte(`"dGhpc/9pc/9h/3Rlc3Q"`)
	want := "this\xffis\xffa\xfftest"
	var got Base64String
	err := json.Unmarshal(input, &got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("json.Unmarshal(%q): wanted %q got %q", string(input), want, string(got))
	}
}

func TestMarshalBase64Struct(t *testing.T) {
	input := struct{ Value Base64String }{Base64String("this\xffis\xffa\xfftest")}
	want := `{"Value":"dGhpc/9pc/9h/3Rlc3Q"}`
	got, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("json.Marshal(%v): wanted %q got %q", input, want, string(got))
	}
}

func TestMarshalBase64Map(t *testing.T) {
	input := map[string]Base64String{"Value": Base64String("this\xffis\xffa\xfftest")}
	want := `{"Value":"dGhpc/9pc/9h/3Rlc3Q"}`
	got, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("json.Marshal(%v): wanted %q got %q", input, want, string(got))
	}
}

func TestMarshalBase64Slice(t *testing.T) {
	input := []Base64String{Base64String("this\xffis\xffa\xfftest")}
	want := `["dGhpc/9pc/9h/3Rlc3Q"]`
	got, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("json.Marshal(%v): wanted %q got %q", input, want, string(got))
	}
}
