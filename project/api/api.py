import json
import flask
import math
from flask import request
from numbers import Number
from flask_celery import make_celery
from binance.enums import *
from binance.exceptions import *
from binance.client import Client

app = flask.Flask(__name__)
app.config.update(
    CELERY_BROKER_URL='pyamqp://',
    CELERY_RESULT_BACKEND='rpc://'
)

celery = make_celery(app)

@app.route('/bcube/api/v1/signal', methods=['POST'])
def process_signal():
    req_data = request.get_json()
    
    signal = req_data['signal']
    keys = req_data['keys']
    
    # faire une validation des paramètres du signal
    result = json.loads(validate_signal(signal))
    signal_is_valid = result['valid']
    message = result['message']
    
    # si le signal est valide,
    if(signal_is_valid):
        # extraire les parmètres du signal
        crypto = signal['crypto']
        pairing = signal['pairing']
        range_low = signal['range_low']
        range_high = signal['range_high']
        target = signal['targets'][0]
        stoploss = signal['stoploss']
        
        # si la liste de clés n'est pas vide,
        result_array = []
        if keys:
            i = 0
            # pour chaque couple (clé publique, clé privée), soumettre des OCOs
            for key in keys:
                result = {}
                api_key = key['public_key']
                api_secret = key['private_key']
                result['api_key'] = api_key
                buy_result = send_buy_oco_order.delay(api_key=api_key, 
                                                             api_secret=api_secret, 
                                                             crypto=crypto, 
                                                             pairing=pairing,
                                                             range_low=range_low, 
                                                             range_high=range_high)
                #print(buy_result)
                result['buy_task_id'] = buy_result.id
                sell_result = send_sell_oco_order.delay(api_key=api_key, 
                                                               api_secret=api_secret, 
                                                               crypto=crypto, 
                                                               pairing=pairing, 
                                                               target=target, 
                                                               stoploss=stoploss)
                #print(sell_result)
                result['sell_task_id'] = sell_result.id
                result_array.append(result)
                i = i + 1
            return json.dumps(result_array)
        else:
            return "The keys is empty."
    else:
        return message
        
def validate_signal(signal):
    data = {}
    
    range_low = signal['range_low']
    range_high = signal['range_high']
    target = signal['targets'][0]
    stoploss = signal['stoploss']
    
    if(not isinstance(range_low, Number) or range_low <= 0):
        data['valid'] = False
        data['message'] = 'The range low should be a positive number'
        result = json.dumps(data)
        return result
    if(not isinstance(range_high, Number) or range_high <= 0):
        data['valid'] = False
        data['message'] = 'The range high should be a positive number'
        result = json.dumps(data)
        return result
    if(range_low >= range_high):
        data['valid'] = False
        data['message'] = 'The range high should be greater than the range low'
        result = json.dumps(data)
        return result
    if( not isinstance(target, Number) or target <= 0):
        data['valid'] = False
        data['message'] = 'The target should be a positive number'
        result = json.dumps(data)
        return result
    if(not isinstance(stoploss, Number) or stoploss <= 0):
        data['valid'] = False
        data['message'] = 'The stoploss should be a positive number'
        result = json.dumps(data)
        return result
    if(stoploss >= target):
        data['valid'] = False
        data['message'] = 'The target should be greater than the stoploss'
        result = json.dumps(data)
        return result
    
    data['valid'] = True
    data['message'] = 'The signal is valid'
    result = json.dumps(data)
    return result

@celery.task(name='bcube_api.send_sell_oco_order')
def send_sell_oco_order(api_key, api_secret, crypto, pairing, target, stoploss):
    client = Client(api_key, api_secret)
    
    symbol = crypto + pairing
    
    symbol_info = client.get_symbol_info(symbol)
    if symbol_info is None:
        raise Exception("The pair "+symbol+" is not valid.")
    else:
        minQty = client.get_symbol_info(symbol)['filters'][2]['minQty']

    precision = int(round(-1*math.log(float(minQty),10),0))

    balance = client.get_asset_balance(asset=crypto)
    free_crypto = float(balance['free'])
    
    if(float(free_crypto) > float(minQty)):
        try:
            free_crypto = "{:0.0{}f}".format(free_crypto, precision)

            oco_order = client.create_oco_order(
                symbol=symbol,
                side=SIDE_SELL,
                stopLimitTimeInForce=TIME_IN_FORCE_GTC,
                quantity=free_crypto,
                stopPrice=stoploss,
                stopLimitPrice=stoploss,
                price=target)
                
        except Exception as e:
            raise e
        else:
            return oco_order
    else:
        raise Exception("The available quantity is lower than the minimun tradable quantity")

@celery.task(name='bcube_api.send_buy_oco_order')
def send_buy_oco_order(api_key, api_secret, crypto, pairing, range_low, range_high):
    client = Client(api_key, api_secret)
    
    symbol = pairing + crypto
    
    symbol_info = client.get_symbol_info(symbol)
    if symbol_info is None:
        raise Exception("The pair "+symbol+" is not valid.")
    else:
        minQty = client.get_symbol_info(symbol)['filters'][2]['minQty']
    
    precision = int(round(-1*math.log(float(minQty),10),0))
    
    balance = client.get_asset_balance(asset=crypto)
    free_pairing = float(balance['free'])
    
    if(float(free_pairing) > float(minQty)):
        try:
            quantity = float(free_pairing)/float(range_high)
            quantity = "{:0.0{}f}".format(quantity, precision)
            
            oco_order = client.create_oco_order(
                symbol=symbol,
                side=SIDE_BUY,
                stopLimitTimeInForce=TIME_IN_FORCE_GTC,
                quantity=quantity,
                stopPrice=range_high,
                stopLimitPrice=range_high,
                price=range_low)
        except Exception as e:
            raise e
        else:
            return oco_order
    else:
        raise Exception("The available quantity is lower than the minimun tradable quantity")

if(__name__== '__main__'):
    app.run(debug=True)
