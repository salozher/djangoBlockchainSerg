from django.contrib import admin
from django.urls import path
from .views import (
    new_transaction,
    get_transactions_buffer,
    get_nodes_list,
    get_full_chain,
    register,
    resolve,
    home_view,
    mine,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('mine/', mine, name='mine'),
    path('transactions/new/', new_transaction, name='new_transaction'),
    path('transactions/buffer/', get_transactions_buffer, name='get_transactions_buffer'),
    path('chain/', get_full_chain, name='chain'),
    path('nodes/list/', get_nodes_list, name='get_nodes_list'),
    path('nodes/register/', register, name='register'),
    path('nodes/resolve/', resolve, name='resolve'),
    path('', home_view, name='home_view'),
]
