# Non-Functional Requirements

## NFR-01: Security
The system shall securely handle AWS credentials and sensitive IAM information. AWS access shall follow the principle of least privilege, and the collector should use read-only permissions wherever possible.

## NFR-02: Performance
The system shall process collected IAM information and generate risk findings, relationship graphs and anomaly scores within a reasonable execution time for the supported dataset size.

## NFR-03: Scalability
The system shall support increasing numbers of IAM users, roles, policies and resources without requiring major architectural changes.

## NFR-04: Reliability
The system shall handle missing, incomplete or malformed IAM data without terminating the entire analysis pipeline unexpectedly.

## NFR-05: Accuracy
The system shall produce risk findings and access-verification results based on the available policy information and clearly identify cases where insufficient information prevents a conclusive result.

## NFR-06: Explainability
The system shall provide understandable explanations for identified risks, anomaly scores, verification outcomes and remediation recommendations.

## NFR-07: Usability
The system shall provide an intuitive dashboard that allows administrators and security analysts to navigate IAM identities, security findings, access paths and recommendations.

## NFR-08: Maintainability
The system shall use a modular architecture that separates data collection, identity classification, policy analysis, graph construction, anomaly detection and dashboard presentation.

## NFR-09: Compatibility
The system shall be implemented using Python and compatible libraries and shall support execution in a suitable environment with access to the required AWS services and APIs.

## NFR-10: Availability of Analysis
The system shall support offline analysis using sample or previously collected IAM data when a live AWS connection is unavailable.

## NFR-11: Data Integrity
The system shall preserve the original collected IAM attributes during normalization and analysis and avoid unintended modification of source security configurations.

## NFR-12: Testability
The system shall support automated unit and integration testing to verify the correctness of individual modules and the overall analysis pipeline.

## NFR-13: Extensibility
The system shall allow additional IAM risk rules, anomaly-detection techniques, event sources and verification mechanisms to be incorporated without requiring a complete redesign.

## NFR-14: Auditability
The system shall retain sufficient evidence and contextual information for security findings to allow administrators to understand and investigate detected misconfigurations.