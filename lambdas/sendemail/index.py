###############################################################################
### Imports
###############################################################################
import boto3
from botocore.exceptions import ClientError
import csv
import io
import json
import logging
from datetime import datetime
from io import StringIO

###############################################################################
### Boto Clients
###############################################################################
s3 = boto3.client("s3")
ses = boto3.client("ses")


###############################################################################
### Logger Instance
###############################################################################
logger = logging.getLogger()
logger.setLevel(logging.INFO)


###############################################################################
### Functions
###############################################################################
def generate_presigned_url(bucket_name, key, expiration=84000):
    """Generate a presigned URL for the S3 object."""
    logger.info(
        f"Generating presigned URL for S3 object: s3://{bucket_name}/{key}"
    )

    try:
        # Generate the URL
        url = s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": bucket_name, "Key": key},
            ExpiresIn=expiration,
        )

        logger.info(f"Presigned URL: {url}")

        return url
    except Exception as e:
        logger.error(f"Error generating presigned URL: {e}")
        return None


def get_csv_size_s3(bucket_name, key):
    """Get the size of a CSV file in S3."""
    logger.info(f"Getting CSV file size from S3: s3://{bucket_name}/{key}")

    # Get the CSV file from S3
    obj = s3.get_object(Bucket=bucket_name, Key=key)

    # Get the content length
    file_size = obj["ContentLength"]

    # Convert size to MB for better readability
    file_size_mb = file_size / (1024 * 1024)

    logger.info(f"CSV file size: {file_size_mb} MB")

    if file_size_mb > 10:
        logger.info("File size exceeds 10 MB.")
        return True
    else:
        logger.info("File size is less than 10 MB.")
        return False


def read_csv_from_s3(bucket_name, key):
    """Read a CSV file from S3 and return its content."""
    logger.info(f"Reading CSV file from S3: s3://{bucket_name}/{key}")

    # Get the CSV file from S3
    obj = s3.get_object(Bucket=bucket_name, Key=key)

    # Read the content of the file
    csv_content = obj["Body"].read().decode("utf-8")

    # Use StringIO to simulate a file object from the CSV content
    csv_file = StringIO(csv_content)

    return csv_file.getvalue()


def send_email(
    body_text,
    recipient_emails,
    sender_email,
    subject,
    charset="utf-8",
    csv_content=None,
    bucket_name=None,
    file_size_mb=None,
    # filename=None,
    key=None,
    presigned_url=None,
):
    logger.info("Sending email...")

    # Get the current date
    current_date = datetime.now()

    # Format the date as MMDDYYYY
    date_str = current_date.strftime("%m%d%Y")

    if not presigned_url:
        logger.info("Sending email with attachment")

        # Attachment Filename
        filename = f"securityhub-findings-{date_str}.csv"

        # Send Email
        try:
            response = ses.send_raw_email(
                Source=sender_email,
                Destinations=recipient_emails,
                RawMessage={
                    "Data": (
                        f"From: {sender_email}\n"
                        f"To: {', '.join(recipient_emails)}\n"
                        f"Subject: {subject}\n"
                        "MIME-Version: 1.0\n"
                        'Content-Type: multipart/mixed; boundary="NextPart"\n\n'
                        "--NextPart\n"
                        f"Content-Type: text/plain; charset={charset}\n\n"
                        f"{body_text}\n\n"
                        "--NextPart\n"
                        "Content-Type: text/csv;\n"
                        f'Content-Disposition: attachment; filename="{filename}"\n\n'
                        f"{csv_content}\n\n"
                        "--NextPart--"
                    )
                },
            )

            logger.info("Email sent! Message ID:"),
            logger.info(response["MessageId"])

            return response

        except Exception as e:
            logger.error(
                f"Error sending email: {e.response['Error']['Message']}"
            )
            return False
    elif presigned_url:
        logger.info("Sending email with presigned URL")

        # Form Body Text
        body_text = f"""
        Hello,

        The file you requested from S3 is too large to process directly. You can download it using the following link:

        Presigned URL: {presigned_url}

        File size: {file_size_mb:.2f} MB
        Bucket: {bucket_name}
        Key: {key}

        The link will expire in one hour. Please download the file before the expiration time.

        Best regards,
        Your Lambda Function
        """

        try:
            # Send the email using SES
            response = ses.send_email(
                Source=sender_email,
                Destination={"ToAddresses": recipient_emails},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {
                        "Text": {"Data": body_text},
                        # "Html": {"Data": body_html},
                    },
                },
            )

        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False


###############################################################################
### Lambda Handler
###############################################################################
def lambda_handler(event, context):
    # Log Event and Context
    logger.info(f"event: {event}")
    logger.info(f"context: {context.__dict__}")

    # Get Email Body Text
    body_text = event.get("BodyText")

    # Get Subject
    subject = event.get("Subject")

    # Get Bucket Name
    bucket_name = event.get("BucketName", None)
    logger.info(f"BucketName: {bucket_name}")

    if not bucket_name:
        logger.error("BucketName is required in the event payload.")
        raise ValueError("BucketName is required in the event payload.")

    # Get Output CSV
    output_csv = event.get("OutputCsv", None)
    logger.info(f"OutputCsv: {output_csv}")

    if not output_csv:
        logger.error("OutputCsv is required in the event payload.")
        raise ValueError("OutputCsv is required in the event payload.")

    # Get Sender Email
    sender_email = event.get("SenderEmail", None)
    logger.info(f"SenderEmail: {sender_email}")

    if not sender_email:
        logger.error("SenderEmail is required in the event payload.")
        raise ValueError("SenderEmail is required in the event payload.")

    # Get Recipient Emails
    recipient_emails = event.get("RecipientEmails", None)
    logger.info(f"RecipientEmails: {recipient_emails}")

    if not recipient_emails:
        logger.error("RecipientEmails is required in the event payload.")
        raise ValueError("RecipientEmails is required in the event payload.")

    csv_data = read_csv_from_s3(bucket_name, output_csv)

    # Check File Size
    file_size = get_csv_size_s3(bucket_name, output_csv)

    if not file_size:
        # Send Email with Attachment
        response = send_email(
            body_text=body_text,
            csv_content=csv_data,
            recipient_emails=recipient_emails,
            sender_email=sender_email,
            subject=subject,
        )
    else:
        expiration = 84600
        presigned_url = generate_presigned_url(
            bucket_name=bucket_name,
            key=output_csv,
            expiration=expiration,
        )
        # Send Email with Presigned URL
        response = send_email(
            body_text=body_text,
            bucket_name=bucket_name,
            file_size_mb=file_size,
            key=output_csv,
            presigned_url=presigned_url,
            recipient_emails=recipient_emails,
            sender_email=sender_email,
            subject=subject,
        )

    if response:
        return {
            "statusCode": 200,
            "body": json.dumps(
                f"Security Hub findings data has been emailed to {', '.join(recipient_emails)}"
            ),
        }
    else:
        return {
            "statusCode": 500,
            "body": json.dumps("Error sending email!"),
        }
