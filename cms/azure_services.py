from azure.storage.blob import BlobServiceClient

from settings.base import AZURE_API_KEY

service = BlobServiceClient(
    account_url="https://bugbusterstoragekt.blob.core.windows.net",
    credential={"account_name": "bugbusterstoragekt", "account_key": AZURE_API_KEY},
)


def upload_blob(data, container_name, blob_name):
    blob_client = service.get_blob_client(container=container_name, blob=blob_name)

    with open(data, "rb") as data:
        blob_client.upload_blob(data)
