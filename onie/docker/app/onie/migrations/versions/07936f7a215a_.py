"""empty message

Revision ID: 07936f7a215a
Revises: 
Create Date: 2017-10-27 00:23:43.383218

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '07936f7a215a'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.rename_table('onie_installer', 'pn_cloud_account')


def downgrade():
    op.rename_table('pn_cloud_account', 'onie_installer')
