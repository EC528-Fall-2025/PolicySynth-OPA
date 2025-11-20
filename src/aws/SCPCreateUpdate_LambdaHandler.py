import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    Lambda function that triggers when an SCP is created or updated
    """
    print("FUNCTION EXECUTED")

    try:
        # get info + log
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        source_ip = detail.get('sourceIPAddress')
        user_identity = detail.get('userIdentity', {})
        user_name = user_identity.get('userName', 'Unknown')
        request_parameters = detail.get('requestParameters', {})
        if 'name' in request_parameters:
            logger.info(f"Policy Name: {request_parameters['name']}")

        logger.info(f"SCP Operation Detected: {event_name}")
        logger.info(f"User: {user_name}")
        logger.info(f"Source IP: {source_ip}")

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'SCP change detected and logged successfully',
                'eventName': event_name
            })
        }

    except Exception as e:
        logger.error(f"Error processing SCP event: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error processing event',
                'error': str(e)
            })
        }
