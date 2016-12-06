aws_sign
========

为请求添加aws signature version 4 签名

#### 使用方法:

##### 实例化一个Signer类

~~~~~~~~~~~~~~~~~~~~~~~~ python
import aws_sign
access_key = 'your access key'
secret_key = 'your secret key'
signer = aws_sign.Signer(access_key, secret_key, service='s3',
                         region='us-east-1', defalut_expires=10)
~~~~~~~~~~~~~~~~~~~~~~~~

###### 参数说明：

- 前两个参数分别为用于计算签名的access key 和secret key

- service：服务名，未指定时，使用默认值's3'

- region：区域名，未指定时，使用默认值'us-east-1'

- default_expires：生成预签名的url时，指定签名的过期时间，未指定时，使用默认值60

##### 构造一个请求，为该请求添加签名，并发送请求

~~~~~~~~~~~~~~~~~~~~~~~~~~python
request = {
    'verb': 'GET',
    'uri': '/',
    'args': {'foo1': 'bar', 'foo2': True, 'foo3': [True, 'bar']},
    'headers': {'Host': 'foo.bar.com'},
    'body': '',
}
signer.add_auth(request, presign=True, sign_payload=True,
                headers_not_to_sign=[], request_date='20200112T000102Z',
                expires=10)

conn = httplib.HTTPConnection('127.0.0.1', 80)
conn.request('GET', request['uri'], '', request['headers'])
resp = conn.getresponse()
~~~~~~~~~~~~~~~~~~~~~~~~~~~

###### 参数说明：
- verb：请求方法如GET， PUT，POST等

- uri：请求路径，也可以包含query string如'/to/some/path?foo&foo1=bar'

- args：请求参数，只有uri中不包含query  string时才能指定该参数，不能同时使用query string和args

- headers：请求头，必须包含Host头

- body：请求的body，如果body为空或者不需要将body的内容加入到签名的计算或者已经计算了body的SHA256并添加到了X-Amz-Content-SHA256请求头中，则可以不指定

- prsign：如果为True，则签名信息将放到query string中，得到预签名的url，如果为False，则签名信息将放到Authorization头中，未指定时，使用默认值False

- sign_payload：是否将请求的body（即payload）加入签名的计算，未指定时，使用默认值False

- headers_not_to_sign：指定哪些请求头不加入到签名的计算，未指定时，默认会将所有的头加入到签名的计算，但是，如果sign_payload为False，仍然不会将头X-Amz-Content-SHA256加入到签名的计算

- request_date：指定签名时使用的请求时间，一般不用指定，默认使用当前时间。当生成预签名的url时，为了让该url在很长的时间内有效，可以将该参数设置为未来的某个时间，如（20901212T000000Z），如果使用当前时间，预签名的url最长有效期为一周

- expires：只有presign为True时才有效，用于指定预签名的url的有效时长，如果未指定，则使用default_expires的值

##### 特别说明：

- 如果传入的request字典中的uri中包含了query string，则request字典中不能包含args项

- 传入的uri是url编码后的uri，如果请求参数放在request字典的args项中，则请求参数名和请求参数值都不需要url编码

- request字典中的body不是必须的，是否需要传入body与参数presign，sign_payload 和request字典中的headers有关

- 参数sign_payload用于控制是否将请求头X-Amz-Content-SHA256加入到签名计算，如果加入，修改该头的内容将导致签名不再正确；如果不加入，则可以随意修改该头的内容，而不影响签名的正确性。如果希望签名后的请求只能用于发送特定的数据，则需要设置sign_payload为True

- 如果sign_payload为True，就需要计算body的SHA256，你可以自己计算，并在request字典的headers项中加入X-Amz-Content-SHA256头，该头的值为body的SHA值。如果request字典的headers中没有X-Amz-Content-SHA256头，则add_auth方法会计算request字典中的body的SHA256，并在request字典的headers中添加X-Amz-Content-SHA256头

- 如果sign_payload为False，你仍然可以在request字典的headers中加入X-Amz-Content-SHA256头，但是该头不会参与签名的计算，如果没有这个头，add_auth方法不会主动添加该头
