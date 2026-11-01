# Functional Requirements

## FR-01: AWS IAM Data Collection
The system shall collect AWS IAM information, including users, roles, groups, attached policies, inline policies and trust relationships using AWS APIs through Boto3.

**Status:** Existing implementation; further collection completeness to be validated.

## FR-02: Identity Classification
The system shall classify collected IAM identities into human, non-human and uncertain categories based on available identity attributes and metadata.

**Status:** Implemented.

## FR-03: IAM Policy Analysis
The system shall analyse IAM permission policies and trust policies to identify potentially insecure configurations, including wildcard permissions, excessive trust relationships and unrestricted resource access.

**Status:** Implemented.

## FR-04: Risk Identification
The system shall identify security risks such as excessive permissions, publicly assumable roles, cross-account trust issues, sensitive resource exposure and privilege-escalation opportunities.

**Status:** Implemented.

## FR-05: Risk Scoring and Prioritisation
The system shall assign risk scores and severity levels to identified findings and prioritise them according to their potential security impact.

**Status:** Implemented.

## FR-06: IAM Relationship Graph Construction
The system shall construct a graph representing relationships between IAM users, roles, external principals and resources, including role-assumption and resource-access relationships.

**Status:** Implemented.

## FR-07: Multi-Hop Access Path Analysis
The system shall identify potential multi-hop access paths through which an IAM identity may obtain indirect access to privileged roles or sensitive resources.

**Status:** Implemented.

## FR-08: Access Verification
The system shall evaluate potential access paths using collected trust and permission policies and classify verification results as allowed, blocked or inconclusive.

**Status:** Implemented using an offline policy-analysis approach, with evaluation limitations.

## FR-09: Privilege Escalation Detection
The system shall identify potentially dangerous permission combinations and role-assumption chains that may enable privilege escalation.

**Status:** Implemented.

## FR-10: Automated Remediation Recommendations
The system shall generate remediation suggestions for identified IAM security findings to help administrators address insecure configurations.

**Status:** Implemented.

## FR-11: Graph-Based Anomaly Detection
The system shall analyse IAM relationship structures using graph embeddings and structural features to identify identities that exhibit unusual relationship patterns.

**Status:** Implemented using Node2Vec-style embeddings and structural features.

## FR-12: Outlier Detection
The system shall apply the Local Outlier Factor (LOF) algorithm to identify structurally unusual IAM identities based on extracted graph features.

**Status:** Implemented.

## FR-13: CloudTrail Event Analysis
The system shall analyse available CloudTrail events to identify suspicious IAM-related activities, including unexpected role assumptions, repeated failed role assumptions and console logins without MFA.

**Status:** Implemented for the currently supported event types.

## FR-14: Security Dashboard
The system shall provide an interactive dashboard to display IAM inventory, risk findings, verification results, remediation recommendations, access graphs, anomaly scores and CloudTrail findings.

**Status:** Implemented using Streamlit.

## FR-15: Security Findings Explanation
The system shall provide supporting information for identified risks, including affected identities, resources, severity levels and recommended remediation actions.

**Status:** Implemented; further evidence-level explanations can be added.

## FR-16: AWS Policy Simulator Integration
The system shall integrate with the AWS IAM Policy Simulator to compare the system's offline access-verification results with AWS policy evaluation results.

**Status:** Planned.

## FR-17: Verification Result Comparison
The system shall compare offline verification results with AWS simulator results and identify disagreements or inconclusive evaluations.

**Status:** Planned.

## FR-18: Runtime Role-Chain Analysis
The system shall analyse chronological CloudTrail events to reconstruct observed sequences of role assumptions and distinguish actual observed activity from potential access paths.

**Status:** Planned enhancement.