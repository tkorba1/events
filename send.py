import asyncio

from azure.eventhub import EventData
from azure.eventhub.aio import EventHubProducerClient
from azure.identity.aio import DefaultAzureCredential

EVENT_HUB_FULLY_QUALIFIED_NAMESPACE = "tkeventnamespace.servicebus.windows.net"
EVENT_HUB_NAME = "eh1"

credential = DefaultAzureCredential()

async def run():
    # Create a producer client to send messages to the event hub.
    # Specify a credential that has correct role assigned to access
    # event hubs namespace and the event hub name.
    producer = EventHubProducerClient(
        fully_qualified_namespace=EVENT_HUB_FULLY_QUALIFIED_NAMESPACE,
        eventhub_name=EVENT_HUB_NAME,
        credential=credential,
    )
    async with producer:
        # Create a batch.
        event_data_batch = await producer.create_batch()

        # Add events to the batch.
        # Open and read the JSON file
        with open('./data/sample_recipt.json', 'r') as file:
            data =  file.read()   

        event_data_batch.add(EventData(data))


        # Send the batch of events to the event hub.
        await producer.send_batch(event_data_batch)

        # Close credential when no longer needed.
        await credential.close()

asyncio.run(run())