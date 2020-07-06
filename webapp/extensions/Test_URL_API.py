from webapp.tasks import site_request, display_site_data, fetch_proxies, rotate_proxies, clean_url_string

def cleanup_url(inputURL):
    if "http" in inputURL:
        return inputURL
    else:
        url_base = clean_url_string(inputURL, False)   # Clean prefix
        return f'https://www.{url_base}'#

def site_lookup(inputURL, optionalOutputHTML):
    inputURL = cleanup_url(inputURL)

    proxies = fetch_proxies()
    proxy_dict = rotate_proxies(proxies, False, True) # Ask for a dict w/ location
    proxy_string = ", ".join(proxy_dict.values())
    proxy = proxy_dict['result']

    response = site_request(
        inputURL=inputURL,
        inputProxy=proxy,
        inputWaitTime=0,
        SoupOrResponse='response',
        optionalReferer=False,
        optionalPrint=True)

    output_dict = display_site_data(response, inputURL, proxy_string, False)

    if optionalOutputHTML:
        output_dict['Content'] = response.text

    return output_dict