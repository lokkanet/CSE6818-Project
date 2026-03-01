import contextlib
from rest_framework.renderers import JSONRenderer
from rest_framework.utils import json
from rest_framework.views import exception_handler


class CustomJSONRenderer(JSONRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        messages = detail = errors = links = count = total_pages = None
        print(data)
        if data is not None:
            detail = (
                data.pop("detail")
                if "detail" in data
                else (data.pop("message") if "message" in data else "")
            )
            messages = (
                data.pop("messages") if "messages" in data else ""
            )
            data = data.pop("data") if "data" in data else data
            links = data.pop("links") if "links" in data else {}
            count = data.pop("count") if "count" in data else 0
            total_pages = data.pop("total_pages") if "total_pages" in data else 0
            data = data.pop("results") if "results" in data else data

        stats_code = renderer_context["response"].status_code
        errors = []

        if stats_code >= 400:
            if detail not in ["", None]:
                errors.append(detail)
            if len(messages) != 0:
                if "message" in messages[0]:
                    errors.append(messages[0]["message"])
            if "errors" in data:
                if type(data["errors"]) != list:
                    errors.append(data.pop("errors"))
                else:
                    errors = data.pop("errors")
                # errors.append(data.pop("errors"))

            if type(data) == dict:
                for dat in data.values():
                    errors.append(dat)
            if type(data) == list:
                for dat in data:
                    errors.append(dat)
            data = None
            detail = ""
            messages = ""
        else:
            errors = [data.pop("errors")] if "errors" in data else []

        response_data = {
            # "detail": errors[0].split(":")[1].strip() if errors else detail,
            "detail": detail,
            "messages": messages,
            "errors": errors,
            "status_code": stats_code,
            "links": links,
            "count": count,
            "total_pages": total_pages,
            "data": data if data else (None if data == {} else []),
        }

        with contextlib.suppress(Exception):
            getattr(
                renderer_context.get("view").get_serializer().Meta,
                "resource_name",
                "objects",
            )

        return super(CustomJSONRenderer, self).render(
            response_data, accepted_media_type, renderer_context
        )


# # custom_exception_handler.py
def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is not None and response.status_code >= 400:
        data = []
        for err in response.data.values():
            if type(err) == list:
                err = err[0]
            data.append(err)
        response.data = {
            "data": data,
        }
    return response
