from rest_framework import pagination
from rest_framework.response import Response
from rest_framework.exceptions import NotFound, ErrorDetail, APIException
from rest_framework import status
from django.utils.translation import gettext_lazy as _
from django.core.paginator import InvalidPage


class NotFoundExtended(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = _("A server error occurred.")
    default_code = "error"

    def __init__(self, detail=None, code=None):
        if detail is None:
            detail = str(self.default_detail)
        if code is None:
            code = str(self.default_code)

        self.detail = detail


class ButFound(APIException):
    status_code = status.HTTP_200_OK
    default_detail = "No data found"
    default_code = 'ok'


class CustomPagination(pagination.PageNumberPagination):
    page_size_query_param = "limit"
    # page_size = 10
    # page_size_query_param = 'page_size'
    max_page_size = 100

    def paginate_queryset(self, queryset, request, view=None):
        page_size = self.get_page_size(request)
        if not page_size:
            return None
        paginator = self.django_paginator_class(queryset, page_size)
        page_number = self.get_page_number(request, paginator)
        try:
            self.page = paginator.page(page_number)
        except InvalidPage as exc:
            msg = self.invalid_page_message.format(
                page_number=page_number, message=str(exc)
            )
            raise ButFound()
            # raise ButFound()


        if paginator.num_pages > 1 and self.template is not None:
            # The browsable API should display pagination controls.
            self.display_page_controls = True

        self.request = request
        return list(self.page)

    def get_paginated_response(self, data):
        if hasattr(self, "page"):
            return Response(
                {
                    "links": {
                        "next": self.get_next_link(),
                        "previous": self.get_previous_link(),
                    },
                    "count": self.page.paginator.count,
                    "total_pages": self.page.paginator.num_pages,
                    "results": data,
                }
            )
        else:
            return Response(
                {
                    "links": {
                        "next": None,
                        "previous": None
                    },
                    "count": len(data),
                    "total_pages": 1,
                    "results": data,
                }
            )

    # def paginate_queryset(self, queryset, request,  view=None):
    #     """
    #     Paginate a queryset if required, either returning a
    #     page object, or `None` if pagination is not configured for this view.
    #     """
    #     page_size = self.get_page_size(request)
    #     if not page_size:
    #         return None
    #
    #     paginator = self.django_paginator_class(queryset, page_size)
    #     page_number = self.get_page_number(request, paginator)
    #
    #     try:
    #         self.page = paginator.page(page_number)
    #
    #     except InvalidPage as exc:
    #         # msg = self.invalid_page_message.format(
    #         #     page_number=page_number, message=str(exc)
    #         # )
    #         if not self.invalid_page_message.format(page_number=page_number, message=str(exc)) == "Invalid page.":
    #             output_data = {
    #                 "links": {
    #                     "next": None,
    #                     "previous": None,
    #                 },
    #                 "count": None,
    #                 "total_pages": None,
    #                 "results": None,
    #             }
    #
    #         else:
    #
    #             output_data = {
    #                 "links": {
    #                     "next": self.get_next_link(),
    #                     "previous": self.get_previous_link(),
    #                 },
    #                 "count": self.page.paginator.count,
    #                 "total_pages": self.page.paginator.num_pages,
    #                 "results": queryset,
    #             }
    #
    #         raise NotFoundExtended(output_data)
    #
    #     if paginator.num_pages > 1 and self.template is not None:
    #         # The browsable API should display pagination controls.
    #         self.display_page_controls = True
    #
    #     self.request = request
    #     return list(self.page)
    #
