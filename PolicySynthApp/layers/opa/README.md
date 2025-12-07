# OPA Lambda Layer

This directory should contain a zip file with the OPA binary structured as follows:

```
opa-layer.zip
└── opt/
    └── bin/
        └── opa
```

## Setup Instructions

1. Extract your OPA layer zip file here, OR
2. Place your `opa-layer.zip` file in this directory and rename it to match the expected structure

The SAM template will automatically package this layer when you run `sam build`.

## Creating the Layer Zip

If you need to create the layer zip from scratch:

```bash
mkdir -p opt/bin
# Download or copy OPA binary to opt/bin/opa
# Make sure it's executable: chmod +x opt/bin/opa
zip -r opa-layer.zip opt/
```

The OPA binary should be compatible with Amazon Linux 2 (the Lambda execution environment).

