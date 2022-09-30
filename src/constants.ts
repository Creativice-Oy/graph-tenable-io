import {
  RelationshipClass,
  RelationshipDirection,
  StepEntityMetadata,
  StepMappedRelationshipMetadata,
  StepRelationshipMetadata,
} from '@jupiterone/integration-sdk-core';

export const StepIds = {
  ACCOUNT: 'step-account',
  ASSETS: 'step-assets',
  VULNERABILITIES: 'step-vulnerabilities',
  VULNERABILITY_CVE_RELATIONSHIPS: 'build-vuln-cve-relationships',
  ASSET_VULNERABILITY_RELATIONSHIPS: 'build-asset-vuln-relationships',
  USERS: 'step-users',
  CONTAINER_IMAGES: 'step-container-images',
  CONTAINER_REPOSITORIES: 'step-container-repositories',
  REPOSITORY_IMAGES_RELATIONSHIPS: 'build-repository-images-relationships',
  CONTAINER_REPORTS: 'step-container-reports',
  CONTAINER_FINDING_CVE_RELATIONSHIPS:
    'build-container-finding-cve-relationships',
  CONTAINER_FINDING_CWE_RELATIONSHIPS:
    'build-container-finding-cwe-relationships',
};

export const Entities: Record<
  | 'ACCOUNT'
  | 'ASSET'
  | 'CONTAINER_IMAGE'
  | 'CONTAINER_REPOSITORY'
  | 'CONTAINER_REPORT'
  | 'CONTAINER_FINDING'
  | 'CONTAINER_MALWARE'
  | 'CONTAINER_UNWANTED_PROGRAM'
  | 'VULNERABILITY'
  | 'USER',
  StepEntityMetadata
> = {
  ACCOUNT: {
    resourceName: 'Account',
    _class: ['Account'],
    _type: 'tenable_account',
  },
  ASSET: {
    resourceName: 'Asset',
    _class: ['Record'],
    _type: 'tenable_asset',
  },
  CONTAINER_IMAGE: {
    resourceName: 'Container Image',
    _class: ['Image'],
    _type: 'tenable_container_image',
  },
  CONTAINER_REPOSITORY: {
    resourceName: 'Container Repository',
    _class: ['Repository'],
    _type: 'tenable_container_repository',
  },
  // TODO does the report entity simply include container details, can we really get rid of this entity?
  CONTAINER_REPORT: {
    resourceName: 'Container Report',
    _class: ['Assessment'],
    _type: 'tenable_container_report',
  },
  CONTAINER_FINDING: {
    resourceName: 'Container Finding',
    _class: ['Finding'],
    _type: 'tenable_container_finding',
  },
  CONTAINER_MALWARE: {
    resourceName: 'Container Malware',
    _class: ['Finding'],
    _type: 'tenable_container_malware',
  },
  CONTAINER_UNWANTED_PROGRAM: {
    resourceName: 'Container Unwanted Program',
    _class: ['Finding'],
    _type: 'tenable_container_unwanted_program',
  },
  VULNERABILITY: {
    resourceName: 'Vulnerability',
    _class: ['Finding'],
    _type: 'tenable_vulnerability_finding',
  },
  USER: {
    resourceName: 'User',
    _class: ['User'],
    _type: 'tenable_user',
  },
};
//TODO fix these
export const Relationships: Record<
  | 'ACCOUNT_HAS_USER'
  | 'ACCOUNT_HAS_ASSET'
  | 'ACCOUNT_HAS_CONTAINER_REPOSITORY'
  | 'ACCOUNT_HAS_CONTAINER_IMAGE'
  | 'CONTAINER_REPOSITORY_HAS_IMAGE'
  | 'CONTAINER_IMAGE_HAS_REPORT'
  | 'CONTAINER_IMAGE_HAS_FINDING'
  | 'CONTAINER_IMAGE_HAS_MALWARE'
  | 'CONTAINER_IMAGE_HAS_UNWANTED_PROGRAM'
  | 'REPORT_IDENTIFIED_FINDING'
  | 'REPORT_IDENTIFIED_MALWARE'
  | 'REPORT_IDENTIFIED_UNWANTED_PROGRAM'
  | 'ASSET_HAS_VULN',
  StepRelationshipMetadata
> = {
  ACCOUNT_HAS_USER: {
    _type: 'tenable_account_has_user',
    sourceType: Entities.ACCOUNT._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.USER._type,
  },
  ACCOUNT_HAS_ASSET: {
    _type: 'tenable_account_has_asset',
    sourceType: Entities.ACCOUNT._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.ASSET._type,
  },
  ACCOUNT_HAS_CONTAINER_REPOSITORY: {
    _type: 'tenable_account_has_container_repository',
    sourceType: Entities.ACCOUNT._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.CONTAINER_REPOSITORY._type,
  },
  CONTAINER_REPOSITORY_HAS_IMAGE: {
    _type: 'tenable_container_repository_has_image',
    sourceType: Entities.CONTAINER_REPOSITORY._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.CONTAINER_IMAGE._type,
  },
  ACCOUNT_HAS_CONTAINER_IMAGE: {
    _type: 'tenable_account_has_container_image',
    sourceType: Entities.ACCOUNT._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.CONTAINER_IMAGE._type,
  },
  CONTAINER_IMAGE_HAS_REPORT: {
    _type: 'tenable_container_image_has_report',
    sourceType: Entities.CONTAINER_IMAGE._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.CONTAINER_REPORT._type,
  },
  CONTAINER_IMAGE_HAS_FINDING: {
    _type: 'tenable_container_image_has_finding',
    sourceType: Entities.CONTAINER_IMAGE._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.CONTAINER_FINDING._type,
  },
  CONTAINER_IMAGE_HAS_MALWARE: {
    _type: 'tenable_container_image_has_malware',
    sourceType: Entities.CONTAINER_IMAGE._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.CONTAINER_MALWARE._type,
  },
  CONTAINER_IMAGE_HAS_UNWANTED_PROGRAM: {
    _type: 'tenable_container_image_has_unwanted_program',
    sourceType: Entities.CONTAINER_IMAGE._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.CONTAINER_UNWANTED_PROGRAM._type,
  },
  REPORT_IDENTIFIED_FINDING: {
    _type: 'tenable_container_report_identified_finding',
    sourceType: Entities.CONTAINER_REPORT._type,
    _class: RelationshipClass.IDENTIFIED,
    targetType: Entities.CONTAINER_FINDING._type,
  },
  REPORT_IDENTIFIED_MALWARE: {
    _type: 'tenable_container_report_identified_malware',
    sourceType: Entities.CONTAINER_REPORT._type,
    _class: RelationshipClass.IDENTIFIED,
    targetType: Entities.CONTAINER_MALWARE._type,
  },
  REPORT_IDENTIFIED_UNWANTED_PROGRAM: {
    _type: 'tenable_container_report_identified_unwanted_program',
    sourceType: Entities.CONTAINER_REPORT._type,
    _class: RelationshipClass.IDENTIFIED,
    targetType: Entities.CONTAINER_UNWANTED_PROGRAM._type,
  },
  ASSET_HAS_VULN: {
    _type: 'tenable_asset_has_vulnerability_finding',
    sourceType: Entities.ASSET._type,
    _class: RelationshipClass.HAS,
    targetType: Entities.VULNERABILITY._type,
  },
};

export const MappedRelationships: Record<
  | 'ASSET_IS_AWS_INSTANCE'
  | 'ASSET_IS_AZURE_VM'
  | 'ASSET_IS_GOOGLE_COMPUTE_INSTANCE'
  | 'ASSET_IS_TENABLE_ASSET'
  | 'AWS_INSTANCE_HAS_VULN'
  | 'AZURE_VM_HAS_VULN'
  | 'GOOGLE_COMPUTE_INSTANCE_HAS_VULN'
  | 'TENABLE_ASSET_HAS_VULN'
  | 'VULNERABILITY_IS_CVE'
  | 'CONTAINER_FINDING_IS_CVE'
  | 'CONTAINER_FINDING_EXPLOITS_CWE',
  StepMappedRelationshipMetadata
> = {
  ASSET_IS_AWS_INSTANCE: {
    _type: 'tenable_asset_is_aws_instance',
    sourceType: Entities.ASSET._type,
    _class: RelationshipClass.IS,
    targetType: 'aws_instance',
    direction: RelationshipDirection.FORWARD,
  },
  ASSET_IS_AZURE_VM: {
    _type: 'tenable_asset_is_azure_vm',
    sourceType: Entities.ASSET._type,
    _class: RelationshipClass.IS,
    targetType: 'azure_vm',
    direction: RelationshipDirection.FORWARD,
  },
  ASSET_IS_GOOGLE_COMPUTE_INSTANCE: {
    _type: 'tenable_asset_is_google_compute_instance',
    sourceType: Entities.ASSET._type,
    _class: RelationshipClass.IS,
    targetType: 'google_compute_instance',
    direction: RelationshipDirection.FORWARD,
  },
  ASSET_IS_TENABLE_ASSET: {
    _type: 'tenable_asset_is_tenable_asset',
    sourceType: Entities.ASSET._type,
    _class: RelationshipClass.IS,
    targetType: 'tenable_asset',
    direction: RelationshipDirection.FORWARD,
  },
  AWS_INSTANCE_HAS_VULN: {
    _type: 'aws_instance_has_tenable_vulnerability_finding',
    sourceType: Entities.VULNERABILITY._type,
    _class: RelationshipClass.HAS,
    targetType: 'aws_instance',
    direction: RelationshipDirection.REVERSE,
  },
  AZURE_VM_HAS_VULN: {
    _type: 'azure_vm_has_tenable_vulnerability_finding',
    sourceType: Entities.VULNERABILITY._type,
    _class: RelationshipClass.HAS,
    targetType: 'azure_vm',
    direction: RelationshipDirection.REVERSE,
  },
  GOOGLE_COMPUTE_INSTANCE_HAS_VULN: {
    _type: 'google_compute_instance_has_tenable_vulnerability_finding',
    sourceType: Entities.VULNERABILITY._type,
    _class: RelationshipClass.HAS,
    targetType: 'google_compute_instance',
    direction: RelationshipDirection.REVERSE,
  },
  TENABLE_ASSET_HAS_VULN: {
    _type: 'tenable_asset_has_tenable_vulnerability_finding',
    sourceType: Entities.VULNERABILITY._type,
    _class: RelationshipClass.HAS,
    targetType: 'tenable_asset',
    direction: RelationshipDirection.REVERSE,
  },
  VULNERABILITY_IS_CVE: {
    _type: 'tenable_vulnerability_finding_is_cve',
    sourceType: Entities.VULNERABILITY._type,
    _class: RelationshipClass.IS,
    targetType: 'cve',
    direction: RelationshipDirection.FORWARD,
  },
  CONTAINER_FINDING_IS_CVE: {
    _type: 'tenable_container_finding_is_cve',
    sourceType: Entities.CONTAINER_FINDING._type,
    _class: RelationshipClass.IS,
    targetType: 'cve',
    direction: RelationshipDirection.FORWARD,
  },
  CONTAINER_FINDING_EXPLOITS_CWE: {
    _type: 'tenable_container_finding_exploits_cwe',
    sourceType: Entities.CONTAINER_FINDING._type,
    _class: RelationshipClass.EXPLOITS,
    targetType: 'cwe',
    direction: RelationshipDirection.FORWARD,
  },
};

export enum HostTypes {
  TENABLE_ASSET = 'tenable_asset',
  AWS_INSTANCE = 'aws_instance',
  AZURE_VM = 'azure_vm',
  GOOGLE_COMPUTE_INSTANCE = 'google_compute_instance',
}
