## **1. Application startup and enviroment**
| Check | Recorded result |
| --- | --- |
| Flask startup | Started successfully in approximately 9 seconds |
| Startup messages | Reported running on all addresses |
| Startup warning | Development server warning observed |
| Flask container | `original-app-flask-1`, running; internal port `5000/tcp` |
| NGINX container | `original-app-nginx-1`, running; ports `80/tcp` and `443` published to the host |
| Docker images | `nginx:alpine`, `majodockerid/uwe:application3`, `original-app-flask:latest`, `original-app-nginx:latest` |
| Test file | `test_plain.txt` |
| Test file content | `TESTFILE-12345 this is plaintext for Application_3` |
| Test file creation | Created successfully |

## **2. Browser and application behaviour**

| Check | Your recorded result |
| --- | --- |
| First address attempted | `https://localhost` |
| First attempt | Application did not load because Firefox automatically upgraded to HTTPS and displayed a secure connection error. |
| Alternative address | `http://172.23.0.2:5000` |
| Alternative address loaded | Yes |
| Home page | Displayed an upload-a-file-for-encryption page. |
| Upload option | Browse file button |
| Application action | Upload and Encrypt button |
| Separate decrypt function | No decrypt function was visible in the application. |

## **3. Upload and encryption results**

Recorded results

| Check | Your recorded result |
| --- | --- |
| Upload request URL | `http://172.23.0.2:5000/upload` |
| Request method | POST |
| HTTP status code | 200 |
| Response | Returned the saved file location and encryption key |
| Encryption endpoint shown | `http://172.23.0.2:5000/upload` |
| Encryption key | `197` |
| Encryption save message | `file saved to /tmp/test_plain.txt.enc` |
| Saved file path | `/tmp/test_plain.txt.enc` |

## **4. Decryption results**

| Check | Your recorded result |
| --- | --- |
| Decryption function visible | No |
| Decryption attempted | No separate decrypt function was available |
| Decryption outcome | Not tested |
| Original instructions' expected functionality | Encryption and decryption |

## **5. File storage results**

| Check | Your recorded result |
| --- | --- |
| File appeared in `/tmp` | Yes |
| Filename | `test_plain.txt.enc` |
| File size | 51 bytes |
| File owner | `root` |
| File permissions | `-rw-r--r--` |
| File copied out of container | Yes |
| Original file readable | Yes |
| Saved file readable | No |
| Saved file appearance | Unreadable characters |
| Original file size | 51 bytes |
| Saved file size | 51 bytes |

Your recorded permissions mean:

- Owner (`root`): read and write.
- Group: read.
- Other users: read.

This is an observation, not yet a conclusion about whether the permissions are appropriate.

## **6. Application user and logging**

| Check | Your recorded result |
| --- | --- |
| `whoami` output | `root` |
| Timestamp in logs | Present |
| IP address in logs | Present |
| Requested URL/endpoint | Present |
| Action information | Encryption action shown |
| Request success/failure information | Present |
| Upload outcome | Logs showed the encryption outcome, including the encryption key and file location. |

One particularly important observation is that your notes say the logs included the encryption key and saved file location. Keep the original log evidence, but redact the key from any presentation screenshots or material you share publicly.

## **7. HTTP and HTTPS results**

Recorded results

| Test | Your recorded result | Server header |
| --- | --- | --- |
| HTTPS port 443 | `curl: (35) OpenSSL/3.0.13: error:0A00010B:SSL routines::wrong version number` | Not recorded |
| HTTP port 443 | `HTTP/1.1 200 OK` | `nginx/1.31.8` |
| HTTP port 80 | `curl: (7) Failed to connect to localhost port 80 after 1 ms: Couldn't connect to server` | Not recorded |

These are the results exactly as recorded in your notes. They are useful evidence for the later configuration assessment.

## **8. File persistence after restart**

| Check | Your recorded result |
| --- | --- |
| Restart method | `docker compose down` followed by `docker compose up -d` |
| File remained in original location | No |
| Recorded observation | The original location no longer contained the uploaded file after the restart. |

This is an important baseline observation for your later storage and persistence assessment.

## **9. Architecture and evidence**

| Check | Your recorded result |
| --- | --- |
| Browser | Accessed Flask directly using `http://172.23.0.2:5000` |
| NGINX | Present in Docker environment |
| Flask | Present in Docker environment |
| File storage | `/tmp/test_plain.txt.enc` |
| Flask user | `root` |
| File persistence | File did not survive `docker compose down` and `docker compose up -d` |
| Architecture diagram | Not yet included in your notes |
