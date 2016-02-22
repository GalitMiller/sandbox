"""Version 1.5.3

Revision ID: 4c41b66b9e05
Revises: 23d4e9ee642f
Create Date: 2015-07-17 16:48:55.283486

"""

# revision identifiers, used by Alembic.
revision = '4c41b66b9e05'
down_revision = '23d4e9ee642f'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # Policy -----------------------------------------------------------------
    with op.batch_alter_table('policy') as batch_op:
        # Add `last_applied_at` and  `last_applied_by_id` columns.
        batch_op.add_column(sa.Column('last_applied_at', sa.DateTime,
                                      nullable=True))
        batch_op.add_column(sa.Column('last_applied_by_id', sa.Integer,
                                      nullable=True))
        batch_op.create_foreign_key('policy_ibfk_2', 'user',
                                    ['last_applied_by_id'], ['id'])

    # Rename `author_id` column to `created_by_id`.
    op.drop_constraint('policy_ibfk_1', 'policy', type_='foreignkey')
    op.alter_column('policy', 'author_id',
                    new_column_name='created_by_id',
                    type_=sa.Integer,
                    existing_type=sa.Integer,
                    existing_nullable=True)
    op.create_foreign_key('policy_ibfk_1', 'policy', 'user',
                          ['created_by_id'], ['id'])

    # Signature --------------------------------------------------------------
    # Rename `author_id` column to `created_by_id`.
    op.drop_constraint('signature_ibfk_5', 'signature', type_='foreignkey')
    op.alter_column('signature', 'author_id',
                    new_column_name='created_by_id',
                    type_=sa.Integer,
                    existing_type=sa.Integer,
                    existing_nullable=True)
    op.create_foreign_key('signature_ibfk_5', 'signature', 'user',
                          ['created_by_id'], ['id'])

    # Policy Application Group -----------------------------------------------
    with op.batch_alter_table('policy_application_group') as batch_op:
        # Add `last_applied_at` and `last_applied_by_id` columns.
        batch_op.add_column(sa.Column('last_applied_at', sa.DateTime,
                                      nullable=True))
        batch_op.add_column(sa.Column('last_applied_by_id', sa.Integer,
                                      nullable=True))
        batch_op.create_foreign_key('policy_application_group_ibfk_2', 'user',
                                    ['last_applied_by_id'], ['id'])


def downgrade():
    # Policy -----------------------------------------------------------------
    with op.batch_alter_table('policy') as batch_op:
        batch_op.drop_column('last_applied_at')
        batch_op.drop_constraint('policy_ibfk_2', type_='foreignkey')
        batch_op.drop_column('last_applied_by_id')

    # Rename `created_by_id` column to `author_id`.
    op.drop_constraint('policy_ibfk_1', 'policy', type_='foreignkey')
    op.alter_column('policy', 'created_by_id',
                    new_column_name='author_id',
                    type_=sa.Integer,
                    existing_type=sa.Integer,
                    existing_nullable=True)
    op.create_foreign_key('policy_ibfk_1', 'policy', 'user',
                          ['author_id'], ['id'])

    # Signature --------------------------------------------------------------
    # Rename `created_by_id` column to `author_id`.
    op.drop_constraint('signature_ibfk_5', 'signature', type_='foreignkey')
    op.alter_column('signature', 'created_by_id',
                    new_column_name='author_id',
                    type_=sa.Integer,
                    existing_type=sa.Integer,
                    existing_nullable=True)
    op.create_foreign_key('signature_ibfk_5', 'signature', 'user',
                          ['author_id'], ['id'])

    # Policy Application Group -----------------------------------------------
    with op.batch_alter_table('policy_application_group') as batch_op:
        # Drop `last_applied_at` and `last_applied_by_id` columns.
        batch_op.drop_constraint('policy_application_group_ibfk_2',
                                 type_='foreignkey')
        batch_op.drop_column('last_applied_by_id')
        batch_op.drop_column('last_applied_at')
