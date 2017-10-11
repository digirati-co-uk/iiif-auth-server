# Auth for any resource

## Introduction

Implementing access control for IIIF Image API services treats the image information document (the info.json) as a **probe**. The client can always see the JSON-LD body of the info.json response, but the HTTP status code on the response will vary depending on the user's access to that service. If the info.json returns HTTP 401, the client knows that image requests to that service will also get 401s, and it should look for IIIF auth services in the info.json response to interact with and, if successful, remedy the user's lack of access to the service. 

The resource is the image service, and the 401 response to requests for the resource makes sense. You want to interact with this service? Forbidden! But you can see what you need to do to gain access in the JSON-LD of the service's description document.

The client interacts with the info.json through XHR, where it can read the JSON-LD response. 

How can we extend this pattern to work for other resources that are _not_ services, that _don't_ have a service description that can do double-duty as a probe?

## Other resources

Suppose the resource is a video file, or a PDF, or even a JPEG image. These are not services, they are just regular resources. There's nothing for the client to make an XHR request to in the hope of getting a JSON-LD description back. It's just a binary file. There's no probe.

1. We need somewhere to assert the auth services for our resource
2. we need something for the client to _probe_, to determine the current access to that resource

When the resource is a IIIF Image Service, the info.json does both these jobs, and it feels right that it does these jobs.

The approach taken at Wellcome was (and still is) to assert the auth services directly on the resource in the manifest (meeting requirement 1), and for the client (the UV) to make `HEAD` requests to the resource via XHR, to get a status code (meeting requirement 2). The rest of the auth flow is the same. 

Advantages of this approach:

1. It feels semantically correct. The IIIF Auth services are asserted for the resource via a `service` property, just as the auth services for an image service are asserted. We don't have to invent a surrogate resource to attach the auth services to.
2. The client interacts with the resource directly via HTTP, just as it does for an Image Service.
3. It makes clear the distinction between _service_ resources, and _direct_ resources (for want of better terminology).

Disadvantages:

1. The auth services can only live in the manifest, because there's nowhere else to put them. This can bloat the size of the manifest, as the auth services carry the strings for user display. You can do clever things with auth services in `info.json` responses to get the right messages to your users, which you couldn't do in a manifest.
2. It may be difficult to get your logic in the right place to respond to `HEAD` requests for arbitrary resources, especially if they are served by a CDN or a specialist media platform.
3. The flow is different for image services and binary resources - one is a `GET`, one is a `HEAD`. In practice not a huge difference and not any harder to implement.

## Services description approach

What if we permit a resource's service description to be declared in a separate resource? A `services.json` information document that a client can process for auth the same way it processes an info.json for an image service? This service description could hold any number of services, but it must have the special function of acting as the **probe** for access control information; it's _not just_ a services container - it also represents the content resource for the purposes of probing for access information. We can see how this works easily enough, but what do we think the `services.json` resource is? What profile does it have? It's not one of the existing auth profiles, because it is not itself an auth service. It's the carrier of services, some of which may be auth services. But it plays a special part in auth, as the means of conveying an HTTP status for the resource it is asserted for. It's a kind of proxy, in a looser way than an Image service info.json information document is for parameterised image requests to the service it describes. If we wanted to attach other services to the PDF or JPEG or video (a palette service, or a frame-extraction service, or even a bitstream API endpoint), would they go in the `services.json`? If we attached a bitstream API to a video resource, shouldn't that work exactly like an image API service does now? What does an image resource with auth look like when it also has a IIIF image service attached?

In the following example, the client would see that the resource (a video) has a services information document attached, the profile tells the client that it can use this as an auth probe: in this capacity it acts as a surrogate (for HTTP response statuses) for the video itself. The client loads `services.json` to get the auth services to interact with.

```json
{
    "id": "http://example.org/video.mp4",
    "type": "Video",
    "service": [
        {
            "id": "http://example.org/services/video.mp4/services.json",
            "type": "IIIFServiceService1",
            "profile": "http://iiif.io/api/ext/services_with_a_special_auth_role.json",
            "...": "..."
        }
    ]
}
```

In the next example, the client can see two services. If it wants to show the user `image.jpg` directly, it needs to interact with the auth services in that resource's surrogate `services.json`, and make sure it gets a 200 response on `http://example.org/services/image.jpg/services.json` before setting `image.jpg` as the `src` of an `img` tag. If it wants to pass the image service to Openseadragon as a tile source, it needs to ensure it's getting a 200 on a request for `http://example.org/services/iiif-api/image1.jpg"` (i.e., the current auth spec).

```json
{
    "id": "http://example.org/image1.jpg",
    "type": "Image",
    "service": [
        {
            "id": "http://example.org/services/image.jpg/services.json",
            "type": "IIIFServiceService1",
            "profile": "http://iiif.io/api/ext/services_with_a_special_auth_role.json",
            "...": "...(I have some auth services in me, probe me)..."
        },
        {
            "id": "http://example.org/services/iiif-api/image1.jpg",
            "type": "IIIFImageService2",
            "profile": "http://iiif.io/api/image/2/level1.json",
            "...": "..."
        }
    ]
}
```

Question - should be client be appending `/services.json` to get the json-ld, because it recognises the profile and that pattern mirrors the Image API? It's a bit false, there's nothing else other than the services description to request. 

Question - what does the degraded pattern look like? You're not redirecting to another service; what would you redirect to? Does the services.json need to assert the resource it is for? yes.

The current auth spec is very much designed for auth on services. It has no knowledge of the Presentation API and 

My _client_ demo has no knowledge of the Presentation API either, it only deals with image services.

it needs to come up to Presentation land to demo auth on resources. 