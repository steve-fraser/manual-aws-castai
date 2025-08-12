#!/bin/bash
SUBNET="subnet-0a41e364fb75c31ac"
SG_GROUP="sg-0acaed08afd56140d"
INSTANCE_PROFILE=arn:aws:iam::445567108000:instance-profile/eks-72cc4fab-c18a-1e10-c06f-f81648452d27
CLUSTER_ID="3b909111-a0e7-4b20-a01f-977d37c496be"
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

echo "Node Configuration ID: $NODE_CONFIG_ID"
curl --request POST \
     --url https://api.cast.ai/v1/kubernetes/clusters/$CLUSTER_ID/node-configurations/$NODE_CONFIG_ID/default \
     --header "X-API-Key: $CASTAI_API_TOKEN" \
     --header 'accept: application/json'