###############################################################################
### Imports
###############################################################################
import boto3
import csv
import json
import logging
from datetime import datetime
from io import StringIO

###############################################################################
### Boto Clients
###############################################################################
s3 = boto3.client("s3")


###############################################################################
### Logger Instance
###############################################################################
logger = logging.getLogger()
logger.setLevel(logging.INFO)


###############################################################################
### Functions
###############################################################################
def combine_json_data(bucket_name, prefix):
    """Combine JSON data from multiple files under a specific prefix."""
    logger.info(f"Combining JSON data from S3: {bucket_name}/{prefix}")

    json_data = []

    try:
        # List all JSON files under the prefix
        json_files = list_s3_objects(bucket_name, prefix)

        for json_file in json_files:
            # Read and append JSON data from each file
            data = read_json_from_s3(bucket_name, json_file)
            json_data.extend(data)

        return json_data
    except Exception as e:
        logger.error(f"Error combining JSON data: {str(e)}")
        raise


def list_s3_objects(bucket_name, prefix):
    """List all objects in an S3 bucket under a specific prefix."""
    logger.info(
        f"Listing S3 objects in bucket: {bucket_name}, prefix: {prefix}"
    )
    objects = []

    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

        # Iterate through the listed objects and append their keys to the list
        while response.get("Contents"):
            objects.extend([obj["Key"] for obj in response["Contents"]])

            # If there are more objects, continue to the next batch
            if response["IsTruncated"]:
                response = s3.list_objects_v2(
                    Bucket=bucket_name,
                    Prefix=prefix,
                    ContinuationToken=response["NextContinuationToken"],
                )
            else:
                break

        logger.info(
            f"Found {len(objects)} objects in S3: {bucket_name}/{prefix}"
        )

        return objects
    except Exception as e:
        logger.error(f"Error listing S3 objects: {str(e)}")
        raise


def read_json_from_s3(bucket_name, key):
    """Read JSON data from an S3 object."""
    obj = s3.get_object(Bucket=bucket_name, Key=key)
    return json.loads(obj["Body"].read().decode("utf-8"))


def write_csv_to_s3(bucket_name, output_csv, data, headers):
    """Write CSV data to an S3 object."""
    logger.info(f"Writing CSV data to S3: {bucket_name}/{output_csv}")

    csv_buffer = StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=headers)

    # Write the headers
    writer.writeheader()

    try:
        # Write the data
        for item in data:
            item["securityStandards"] = ", ".join(item["securityStandards"])
            writer.writerow(item)

        # Upload the CSV to S3
        s3.put_object(
            Bucket=bucket_name, Key=output_csv, Body=csv_buffer.getvalue()
        )

        logger.info(f"CSV data written to S3: {bucket_name}/{output_csv}")
    except Exception as e:
        logger.error(f"Error writing CSV data to S3: {str(e)}")
        raise


###############################################################################
### Lambda Handler
###############################################################################
def lambda_handler(event, context):
    # Log Event and Context
    logger.info(f"event: {event}")
    logger.info(f"context: {context.__dict__}")

    # Get current date and format it
    current_date = datetime.now().strftime("%Y-%m-%d")

    # Format Output Key
    output_csv = f"reports/findings_report-{current_date}.csv"
    logger.info(f"Output CSV: {output_csv}")

    # Get the bucket name from the event payload
    bucket_name = event.get("BucketName")
    logger.info(f"BucketName: {bucket_name}")

    if not bucket_name:
        logger.error("BucketName is required in the event payload.")
        raise ValueError("BucketName is required in the event payload.")

    # Prefix for finding stored Security Hub findings
    input_prefix = event.get("Prefix")

    if not input_prefix:
        logger.error("Prefix is required in the event payload.")
        raise ValueError("Prefix is required in the event payload.")

    # Define the CSV file headers
    headers = [
        "awsAccountId",
        "awsAccountName",
        "complianceStatus",
        "controlId",
        "description",
        "findingId",
        "firstSeen",
        "lastSeen",
        "region",
        "remediationText",
        "remediationUrl",
        "resourceArn",
        "severity",
        "title",
        "workflowStatus",
        "securityStandards",
    ]

    # Combine the JSON data from the files in S3
    combined_data = combine_json_data(bucket_name, input_prefix)

    # Write the combined data to a CSV file in S3
    write_csv_to_s3(bucket_name, output_csv, combined_data, headers)

    return output_csv
