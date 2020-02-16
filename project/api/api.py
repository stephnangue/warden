import json
import flask
from flask import request
from binance.client import Client
from binance.enums import *
from binance.exceptions import *
from numbers import Number

app = flask.Flask(__name__)
app.config["DEBUG"] = True

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
        paring = signal['paring']
        range_low = signal['range_low']
        range_high = signal['range_high']
        target = signal['targets'][0]
        stoploss = signal['stoploss']
        
        # si la liste de clés n'est pas vide,
        if keys:
            # pour chaque couple (clé publique, clé privée), soumettre des OCOs
            for key in keys:
                api_key = key['public_key']
                api_secret = key['private_key']
                results = send_oco_orders(api_key=api_key, api_secret=api_secret, crypto=crypto, paring=paring,range_low=range_low, range_high=range_high, target=target, stoploss=stoploss)
            return results
        else:
            return "The keys is empty."
    else:
        return message


def send_oco_orders(api_key, api_secret, crypto, paring, range_low, range_high, target, stoploss):
    client = Client(api_key, api_secret)
    
    balance = client.get_asset_balance(asset=crypto)
    free_crypto = float(balance['free'])
    free_crypto = "{:0.0{}f}".format(free_crypto, 6)
    
    balance = client.get_asset_balance(asset=paring)
    free_paring = float(balance['free'])
    free_paring = "{:0.0{}f}".format(free_paring, 6)
    
    symbol = crypto + paring
    try:
        sell_order = client.create_oco_order(
            symbol=symbol,
            side=SIDE_SELL,
            stopLimitTimeInForce=TIME_IN_FORCE_GTC,
            quantity=free_crypto,
            stopPrice=stoploss+0.1,
            stopLimitPrice=stoploss,
            price=target)

        buy_low_order = client.create_oco_order(
            symbol=symbol,
            side=SIDE_BUY,
            stopLimitTimeInForce=TIME_IN_FORCE_GTC,
            quantity=free_paring*0.5,
            price=range_low)

        buy_high_order = client.create_oco_order(
            symbol=symbol,
            side=SIDE_BUY,
            stopLimitTimeInForce=TIME_IN_FORCE_GTC,
            quantity=free_paring*0.5,
            price=range_high)
            
    except BinanceRequestException as e:
        print(e)
    except BinanceAPIException as e:
        print(e)
    except BinanceOrderException as e:
        print(e)
    except BinanceOrderMinAmountException as e:
        print(e)
    except BinanceOrderMinPriceException as e:
        print(e)
    except BinanceOrderMinTotalException as e:
        print(e)
    except BinanceOrderUnknownSymbolException as e:
        print(e)
    except BinanceOrderInactiveSymbolException as e:
        print(e)
    else:
        return sell_order
    
        
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

app.run()
