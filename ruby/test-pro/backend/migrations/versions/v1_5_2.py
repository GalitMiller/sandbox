"""Version 1.5.2

Revision ID: 23d4e9ee642f
Revises: None
Create Date: 2015-06-22 15:39:31.864839

"""

# revision identifiers, used by Alembic.
revision = '23d4e9ee642f'
down_revision = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    # Signature --------------------------------------------------------------
    with op.batch_alter_table('signature') as batch_op:
        batch_op.add_column(sa.Column('is_editable', sa.Boolean, nullable=True))
        batch_op.add_column(sa.Column('created_at', sa.DateTime, nullable=True))
        batch_op.add_column(sa.Column('author_id', sa.Integer, nullable=True))
        batch_op.create_foreign_key('signature_ibfk_5', 'user', ['author_id'],
                                    ['id'])

    # Signature Category -----------------------------------------------------
    op.add_column('signature_category', sa.Column('description',
                                                  sa.Unicode(255),
                                                  nullable=True))

    # Signature Severity -----------------------------------------------------
    op.alter_column('signature_severity', 'priority',
                    new_column_name='weight',
                    type_=sa.SmallInteger,
                    existing_type=sa.SmallInteger,
                    existing_nullable=False)


def downgrade():
    # Signature --------------------------------------------------------------
    with op.batch_alter_table('signature') as batch_op:
        batch_op.drop_column('is_editable')
        batch_op.drop_column('created_at')
        batch_op.drop_constraint('signature_ibfk_5', type_='foreignkey')
        batch_op.drop_column('author_id')

    # Signature Category -----------------------------------------------------
    op.drop_column('signature_category', 'description')

    # Signature Severity -----------------------------------------------------
    op.alter_column('signature_severity', 'weight',
                    new_column_name='priority',
                    type_=sa.SmallInteger,
                    existing_type=sa.SmallInteger,
                    existing_nullable=False)
