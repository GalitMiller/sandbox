"""Version 1.5.3.1. Drop unique constraint for sensor name.

Revision ID: 24724d9ac135
Revises: 4c41b66b9e05
Create Date: 2015-08-04 17:44:35.923580

"""

# revision identifiers, used by Alembic.
revision = '24724d9ac135'
down_revision = '4c41b66b9e05'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # Sensors ----------------------------------------------------------------
    # Drop unique constraint for `name` column in `sensors` table.
    op.drop_constraint('name', 'sensors', type_='unique')


def downgrade():
    # Sensors ----------------------------------------------------------------
    # Create unique constraint for `name` column in `sensors` table.
    op.create_unique_constraint('name', 'sensors', ['name'])
