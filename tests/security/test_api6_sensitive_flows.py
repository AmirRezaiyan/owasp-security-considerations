from app.vulnerabilities.api6_sensitive_flows import (
    secure_can_purchase,
    vulnerable_can_purchase,
)


def test_sensitive_flow_limits_quantity_stock_and_customer_cap(enable_vulnerable_demos):
    assert vulnerable_can_purchase()
    assert secure_can_purchase(
        quantity=1,
        already_purchased=0,
        available_stock=3,
        customer_limit=2,
    )
    assert not secure_can_purchase(
        quantity=2,
        already_purchased=1,
        available_stock=3,
        customer_limit=2,
    )
    assert not secure_can_purchase(
        quantity=1,
        already_purchased=0,
        available_stock=0,
        customer_limit=2,
    )


def test_sensitive_flow_rejects_negative_counts():
    assert not secure_can_purchase(
        quantity=1,
        already_purchased=-1,
        available_stock=3,
        customer_limit=2,
    )
