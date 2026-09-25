"""Products API — public reads, authenticated writes and deletes.

Endpoints:
  GET    /products               — list all products (public).
  GET    /products/{product_id}  — get a single product (public).
  POST   /products               — create a product (authenticated).
  DELETE /products/{product_id}  — delete a product (owner or admin only).

NOTE — VULN-001 is introduced in Sub-Task 7:
  DELETE currently checks ownership correctly.
  The vulnerability will remove the ownership check.
"""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.database import get_db
from app.models import ProductCreate, ProductResponse

router = APIRouter(prefix="/products", tags=["products"])


@router.get("", response_model=list[ProductResponse])
def list_products(db: Annotated[sqlite3.Connection, Depends(get_db)]):
    """Return all products — no authentication required."""
    rows = db.execute(
        "SELECT id, name, description, price, owner_id FROM products"
    ).fetchall()
    return [ProductResponse(**dict(r)) for r in rows]


@router.get("/{product_id}", response_model=ProductResponse)
def get_product(
    product_id: int,
    db: Annotated[sqlite3.Connection, Depends(get_db)],
):
    """Return a single product by id — no authentication required."""
    row = db.execute(
        "SELECT id, name, description, price, owner_id FROM products WHERE id = ?",
        (product_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )
    return ProductResponse(**dict(row))


@router.post("", response_model=ProductResponse, status_code=status.HTTP_201_CREATED)
def create_product(
    body: ProductCreate,
    current_user: Annotated[sqlite3.Row, Depends(get_current_user)],
    db: Annotated[sqlite3.Connection, Depends(get_db)],
):
    """Create a new product owned by the authenticated user."""
    cursor = db.execute(
        "INSERT INTO products (name, description, price, owner_id) VALUES (?, ?, ?, ?)",
        (body.name, body.description, body.price, current_user["id"]),
    )
    db.commit()
    row = db.execute(
        "SELECT id, name, description, price, owner_id FROM products WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return ProductResponse(**dict(row))


@router.delete("/{product_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_product(
    product_id: int,
    current_user: Annotated[sqlite3.Row, Depends(get_current_user)],
    db: Annotated[sqlite3.Connection, Depends(get_db)],
):
    """Delete a product.  Only the owner or an admin may delete."""
    row = db.execute(
        "SELECT id, owner_id FROM products WHERE id = ?", (product_id,)
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Product not found"
        )

    # VULN-001 (intentional): ownership check removed — any authenticated user
    # can delete any product, regardless of whether they own it.
    db.execute("DELETE FROM products WHERE id = ?", (product_id,))
    db.commit()
