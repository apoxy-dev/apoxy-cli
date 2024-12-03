#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"

# Configurable variables
export GOTOOLCHAIN=go1.23.3 # Should match the go version in go.mod
CODEGEN_VERSION=v0.30.1 # Should match the k8s.io/apimachinery version in go.mod
BOILERPLATE_FILE="${ROOT_DIR}/codegen/boilerplate.go.txt"

# For some reason modern versions of register-gen don't include imports for 
# the runtime and schema packages.
function fixup_register_gen_imports() {
  local root_dir=$1
  local imports=(
    '"k8s.io/apimachinery/pkg/runtime"'
    '"k8s.io/apimachinery/pkg/runtime/schema"'
  )

  find "$root_dir" -type f -name "zz_generated.register.go" | while read -r file; do
    # Check if all imports already exist in the file
    local missing_imports=()
    for import in "${imports[@]}"; do
      if ! grep -q "$import" "$file"; then
        missing_imports+=("$import")
      fi
    done

    # If no imports are missing, skip the file
    if [ ${#missing_imports[@]} -eq 0 ]; then
      continue
    fi

    # Process the file to add missing imports
    awk -v missing_imports="$(printf "%s\n" "${missing_imports[@]}")" '
      BEGIN {
        split(missing_imports, imports, "\n");
        in_imports = 0;
      }
      /import \(/ && !in_imports {
        in_imports = 1;
        print;
        for (i in imports) {
          print "\t" imports[i];
        }
        next;
      }
      in_imports && /\)/ {
        in_imports = 0;
        print;
        next;
      }
      {
        print;
      }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
  done
}

function generate_helpers() {
  local dirs=("$@")
  for dir in "${dirs[@]}"; do
    echo "Generating code for ${dir}/..."

    go run "k8s.io/code-generator/cmd/deepcopy-gen@${CODEGEN_VERSION}" \
      --output-file zz_generated.deepcopy.go \
      --go-header-file "${BOILERPLATE_FILE}" \
      "$dir"

    go run "k8s.io/code-generator/cmd/register-gen@${CODEGEN_VERSION}" \
      --output-file zz_generated.register.go \
      --go-header-file "${BOILERPLATE_FILE}" \
      "$dir"

    fixup_register_gen_imports "$dir"
  done
}

generate_helpers \
  ./api/config/v1alpha1 \
  ./api/controllers/v1alpha1 \
  ./api/core/v1alpha \
  ./api/extensions/v1alpha1 \
  ./api/gateway/v1 \
  ./api/policy/v1alpha1 \
  ./pkg/gateway/gatewayapi \
  ./pkg/gateway/ir

echo "Generating OpenAPI schema..."

# Sadly no published tags.
go run "k8s.io/kube-openapi/cmd/openapi-gen@master" \
  --go-header-file "${BOILERPLATE_FILE}" \
  --output-dir "api/generated" \
  --output-pkg "generated" \
  --output-file zz_generated.openapi.go \
  --report-filename /dev/null \
  k8s.io/api/core/v1 \
  k8s.io/apimachinery/pkg/api/resource \
  k8s.io/apimachinery/pkg/apis/meta/v1 \
  k8s.io/apimachinery/pkg/runtime \
  k8s.io/apimachinery/pkg/util/intstr \
  k8s.io/apimachinery/pkg/version \
  sigs.k8s.io/gateway-api/apis/v1 \
  ./api/controllers/v1alpha1 \
  ./api/core/v1alpha \
  ./api/extensions/v1alpha1 \
  ./api/gateway/v1 \
  ./api/policy/v1alpha1