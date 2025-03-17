import logging
import datetime

class RequestResponseLoggingMiddleware:

    def __init__(self, getResponse):

        self.get_response = getResponse
        self.logger = logging.getLogger('django') # Uses django's logging framework

    def __call__(self, request):

        self.log_request(request)

        response = self.get_response(request)

        self.log_response = (response, request)

        return response

    def log_request(self, request):
        """Logs the details of the incoming request."""
        self.logger.info("--- Incoming Request ---")
        self.logger.info(f"Timestamp: {datetime.datetime.now()}")
        self.logger.info(f"Method: {request.method}")
        self.logger.info(f"URL: {request.path}")
        self.logger.info(f"Headers: {dict(request.headers)}")

        if request.body:

            try:
                self.logger.info(f"Body: {request.body.decode('utf-8')}")

            except UnicodeDecodeError:
                self.logger.info("Body: (non-decodable content)")

    def log_response(self, response, request):
        """Logs the details of the outgoing response."""
        self.logger.info(f"--- Response ---")
        self.logger.info(f"Timestamp: {datetime.datetime.now()}")
        self.logger.info(f"URL: {request.path}")
        self.logger.info(f"Status Code: {response.status_code}")