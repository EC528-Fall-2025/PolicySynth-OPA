
    package aws.scp.Require_Encryption_S3_EBS_RDS
    default allow = false
    default deny = false
    deny[msg] {
        input.action == "s3:PutObject"
        
        msg := "Require-Encryption-S3-EBS-RDS triggered for s3:PutObject"
    }

deny[msg] {
        input.action == "s3:PutObject"
        (not input.s3:x-amz-server-side-encryption or input.s3:x-amz-server-side-encryption != "aws:kms")
        msg := "Require-Encryption-S3-EBS-RDS triggered for s3:PutObject"
    }

deny[msg] {
        input.action == "ec2:CreateVolume"
        input.ec2:Encrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for ec2:CreateVolume"
    }

deny[msg] {
        input.action == "ec2:RunInstances"
        input.ec2:Encrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for ec2:RunInstances"
    }

deny[msg] {
        input.action == "rds:CreateDBInstance"
        input.rds:StorageEncrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for rds:CreateDBInstance"
    }

deny[msg] {
        input.action == "rds:RestoreDBInstanceFromS3"
        input.rds:StorageEncrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for rds:RestoreDBInstanceFromS3"
    }

deny[msg] {
        input.action == "rds:RestoreDBInstanceToPointInTime"
        input.rds:StorageEncrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for rds:RestoreDBInstanceToPointInTime"
    }

deny[msg] {
        input.action == "rds:CreateDBCluster"
        input.rds:StorageEncrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for rds:CreateDBCluster"
    }

deny[msg] {
        input.action == "rds:RestoreDBClusterFromS3"
        input.rds:StorageEncrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for rds:RestoreDBClusterFromS3"
    }

deny[msg] {
        input.action == "rds:RestoreDBClusterToPointInTime"
        input.rds:StorageEncrypted == false
        msg := "Require-Encryption-S3-EBS-RDS triggered for rds:RestoreDBClusterToPointInTime"
    }
