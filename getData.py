import requests, json, urllib2, subprocess, time
from bs4 import BeautifulSoup

def getDateTime():
    return 'Today is %s. It is %s.' % (time.strftime('%A %B %d'), time.strftime('%I:%M %p'))

def getSubway():
    mtaUrl= 'http://service.mta.info/ServiceStatus/status.html'
    soup = BeautifulSoup(urllib2.urlopen(mtaUrl).read(), 'html.parser')
    statuses = soup.find_all('td', {'class': 'subwayCategory'})
    ace = statuses[3].span.contents[0]
    nqr = statuses[8].span.contents[0]
    oneTwoThree = statuses[0].span.contents[0]
    return {
        'ace': 'A C E status: %s.' % (ace),
        'nqr': 'N Q R status: %s.' % (nqr),
        'oneTwoThree': '1 2 3 status: %s.' % (oneTwoThree)
    }

def getWeather():
    key = ''
    city = '5128581'
    weatherUrlC = 'http://api.openweathermap.org/data/2.5/forecast/daily?id=' + city + '&cnt=1&units=metric&APPID=' + key
    weatherUrlF = 'http://api.openweathermap.org/data/2.5/forecast/daily?id=' + city + '&cnt=1&units=imperial&APPID=' + key

    weatherC = json.loads(requests.get(weatherUrlC).content)
    desc = weatherC['list'][0]['weather'][0]['main']
    # morningC = str(int(weatherC['list'][0]['temp']['morn']))
    # dayC = str(int(weatherC['list'][0]['temp']['day']))
    # eveningC = str(int(weatherC['list'][0]['temp']['eve']))

    weatherF = json.loads(requests.get(weatherUrlF).content)
    morningF = str(int(weatherF['list'][0]['temp']['morn']))
    dayF = str(int(weatherF['list'][0]['temp']['day']))
    eveningF = str(int(weatherF['list'][0]['temp']['eve']))
    return {
        'morning': 'Weather: %s. Morning: %s degrees.' % (desc, morningF),
        'day': 'Afternoon: %s degrees.' % (dayF),
        'evening': 'Evening: %s degrees.' % (eveningF)
    }
