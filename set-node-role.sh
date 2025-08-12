#!/bin/bash


# Validate required environment variables
if [[ -z "$CASTAI_API_TOKEN" ]]; then
    echo "Error: CASTAI_API_TOKEN environment variable is required" >&2
    exit 1
fi

# Optional: Validate other required variables
required_vars=("SUBNET" "SG_GROUP" "INSTANCE_PROFILE" "CLUSTER_ID")
for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo "Error: $var is required but not set" >&2
        exit 1
    fi
done

# Display configuration (optional - remove if you don't want to show values)
echo "Configuration:"
echo "  SUBNET: $SUBNET"
echo "  SG_GROUP: $SG_GROUP"
echo "  INSTANCE_PROFILE: $INSTANCE_PROFILE"
echo "  CLUSTER_ID: $CLUSTER_ID"
echo ""

# Create node configuration and capture ID
echo "Creating node configuration..."
NODE_CONFIG_ID=$(curl --silent --request POST \
     --url "https://api.cast.ai/v1/kubernetes/clusters/$CLUSTER_ID/node-configurations" \
     --header "X-API-Key: $CASTAI_API_TOKEN" \
     --header 'accept: application/json' \
     --header 'content-type: application/json' \
     --data @- << EOF | jq -r '.id'
{
  "eks": {
    "imdsV1": true,
    "imdsHopLimit": 2,
    "ipsPerPrefix": 1,
    "imageFamily": "FAMILY_UNSPECIFIED",
    "instanceProfileArn": "$INSTANCE_PROFILE",
    "securityGroups": [
      "$SG_GROUP"
    ]
  },
  "containerRuntime": "UNSPECIFIED",
  "name": "default",
  "subnets": [
    "$SUBNET"
  ]
}
EOF
)

# Check if node configuration was created successfully
if [[ -z "$NODE_CONFIG_ID" || "$NODE_CONFIG_ID" == "null" ]]; then
    echo "Error: Failed to create node configuration" >&2
    exit 1
fi

echo "Node Configuration ID: $NODE_CONFIG_ID"

# Set as default configuration
echo "Setting as default configuration..."
response=$(curl --silent --request POST \
     --url "https://api.cast.ai/v1/kubernetes/clusters/$CLUSTER_ID/node-configurations/$NODE_CONFIG_ID/default" \
     --header "X-API-Key: $CASTAI_API_TOKEN" \
     --header 'accept: application/json')

# Check if setting as default was successful
if [[ $? -eq 0 ]]; then
    echo "Successfully set node configuration as default"
    echo "Response: $response"
else
    echo "Error: Failed to set node configuration as default" >&2
    exit 1
fi