import azure.functions as func
import logging
import json
import os
from jsonschema import validate
from datetime import datetime
import requests

app = func.FunctionApp()

# @app.event_hub_message_trigger(arg_name="azeventhub", event_hub_name="eh1",
#                                connection="tkeventnamespace_RootManageSharedAccessKey_EVENTHUB") 
# def parsexml(azeventhub: func.EventHubEvent):
#     logging.info('Python EventHub trigger processed an event: %s',
#                 azeventhub.get_body().decode('utf-8'))
@app.function_name("HttpFunction1")
@app.route(route="http_trigger_func1", auth_level=func.AuthLevel.ANONYMOUS)
def http_trigger_func(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Starting first http function request .')

    return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
    )
        
        
        
@app.function_name("HttpFunction2")
@app.route(route="http_trigger_func2", auth_level=func.AuthLevel.ANONYMOUS)
def http_trigger_func(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Starting second http function request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )
        
@app.function_name("blob_trigger_func")
@app.blob_trigger(arg_name="myblob", path="demo", connection="AzureWebJobsStorage")

def blob_trigger_func(myblob: func.InputStream):
    logging.info(f"Blob trigger function processed blob \n"
                 f"Name: {myblob.name}\n"
                 f"Blob Size: {myblob.length} bytes")



    
def extract_fields(data: dict) -> dict:
    receipt_data = data['receipt']
    extracted_data = {
        'identifier': receipt_data.get('identifier'),
        'receipt_currency': receipt_data['properties'].get('receipt_currency'),
        'localtime': receipt_data.get('localtime'),
        'transaction_id': receipt_data.get('transaction_id'),
        'total': receipt_data.get('total'),
        'coupon_code': [discount['properties'].get('coupon_code') for discount in receipt_data['discounts']],
        'originating_system_of_receipt': receipt_data['properties'].get('originating_system_of_receipt'),
        'items': [
            {
                'total': item.get('total'),
                'quantity': item.get('quantity'),
                'article_id': item['properties'].get('article_id'),
                'name': item.get('name')
            }
            for item in receipt_data['items']
        ]
    }  
    
    return extracted_data

@app.event_hub_message_trigger(arg_name="azeventhub", event_hub_name="eh1",
                               connection="tkeventnamespace_ListenPolicy_EVENTHUB")
@app.blob_output(arg_name="blobin",
                path="receipts/incoming/recipt.json",
                connection="AzureWebJobsStorage") 
@app.service_bus_topic_output(arg_name="azservicebus",
                              connection="servicebusnamesapace_SERVICEBUS",
                              topic_name="mysbqueue")
def eventhub_trigger_func(azeventhub: func.EventHubEvent, blobin: func.Out[str], azservicebus: func.Out[str]):
  

    try:

        logging.info('Reading data from event hub')
        data = azeventhub.get_body().decode('utf-8')
        
        logging.info('Saving data to blob storage')
        blobin.set(data)
        
        
        logging.info('Reading schema from environment variable')
        json_schema= os.environ.get("json_schema")
        logging.info('Schema loaded successfully')
        
        
        logging.info('Validating data against schema')
        validate(json.loads(data), json.loads(json_schema))
        
        logging.info('Data validated successfully')
        logging.info('Extracting fields from data')
        extracted_data = extract_fields(json.loads(data))
        logging.info('Fields extracted successfully : %s', extracted_data) 
        
        logging.info('Sending data to service bus')
        azservicebus.set(extracted_data)
         
        
    except Exception as e:
        logging.error(f"EventHub trigger function failed: {e}")
        raise e



@app.service_bus_queue_trigger(arg_name="azservicebus", queue_name="mysbqueue",
                               connection="servicebusnamesapace_SERVICEBUS")
@app.blob_output(arg_name="blobout",
                path="receipts/outgoing/extracted.json",
                connection="AzureWebJobsStorage") 

def servicebus_trigger(azservicebus: func.ServiceBusMessage, blobout: func.Out[str]):
    logging.info('Python ServiceBus Queue trigger processed a message: %s',
                azservicebus.get_body().decode('utf-8'))
    logging.info('Saving data to blob storage')
    blobout.set(azservicebus.get_body().decode('utf-8'))
    url = "https://sfsimulation.azurewebsites.net:443/api/sf-receipt/triggers/When_a_HTTP_request_is_received/invoke?api-version=2022-05-01&sp=%2Ftriggers%2FWhen_a_HTTP_request_is_received%2Frun&sv=1.0&sig=NA_77YgW-eMqLMFDG1mWRSAeEJR17vgTFFSFgBcwmt4"

    logging.info('Sending data to HTTP endpoint')
    response = requests.post(url, json=json.loads(azservicebus.get_body().decode('utf-8')))

    logging.info('Response from HTTP endpoint: %s', response)
    azservicebus.
    
