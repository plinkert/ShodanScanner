from mailmerge import MailMerge

def createReport(parstData):
    template = "/home/ja/Desktop/Projects/Scanner/reportTemp.docx"
    document = MailMerge(template)
    document.merge_templates(parstData, separator='page_break')
    document.write('ef1.docx')

def listToString(inputList):
    try:
        if inputList != []:
            result = ', '.join(map(str, inputList))
        else:
            result = ''
        return result
    except:
        return ''
    
def ifExist(dictionary, key):
    if key in dictionary.keys():
        return dictionary[key]
    else:
        return ''

def portData(dataColection):
    resoult = []
    for item in dataColection:
        element = {'port': str(ifExist(item, 'port')), 
        'timestamp': str(ifExist(item, 'timestamp')), 
        'product': ifExist(item, 'product'), 
        'version': ifExist(item, 'version'), 
        'data': ifExist(item, 'data')}
        resoult.append(element)
    return resoult

def vulnsData(dataColection):
    resoult = []
    for item in dataColection:
        element = {'vulns': item,
                   'link': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' +item}
        resoult.append(element)
    return resoult

def parser(inputData):
    parsedData = {}
    parsedData['ip_str'] = inputData['ip_str']
    parsedData['hostnames'] = listToString(inputData['hostnames'])
    parsedData['domains'] = listToString(inputData['domains'])
    parsedData['country_name'] = inputData['country_name']
    parsedData['city'] = inputData['city']
    parsedData['org'] = inputData['org']
    parsedData['isp'] = inputData['isp']
    parsedData['asn'] = inputData['asn']
    parsedData['ports'] = listToString(inputData['ports'])
    
    if 'vulns' in inputData.keys():
        parsedData['vulns'] = vulnsData(inputData['vulns'])
    else:
        parsedData['vulns'] = []
        parsedData['link'] = []
    
    parsedData['port'] = portData(inputData['data'])

    return parsedData
    
