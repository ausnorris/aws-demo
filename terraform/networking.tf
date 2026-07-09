# ── Networking — optional subnet creation ────────────────────────────────────
#
# Set  create_subnets = true  (the default) to let Terraform build two public
# subnets inside your existing VPC.
#
# Set  create_subnets = false  if you already have subnets and want to provide
# their IDs via public_subnet_ids / ecs_subnet_ids instead.
#
# Subnet CIDRs are derived automatically from the VPC's own CIDR block —
# no manual CIDR entry needed.

# ── Discover available AZs ───────────────────────────────────────────────────
data "aws_availability_zones" "available" {
  state = "available"
}

# ── Look up the IGW already attached to the VPC ──────────────────────────────
# Every VPC with internet access has exactly one IGW attached.
# We look it up rather than creating a new one (which would conflict).
data "aws_internet_gateway" "existing" {
  count = var.create_subnets ? 1 : 0

  filter {
    name   = "attachment.vpc-id"
    values = [var.vpc_id]
  }
}

# ── Auto-compute /24 subnet CIDRs from the VPC CIDR ─────────────────────────
# Uses Terraform's cidrsubnet() to carve two /24 subnets at high offsets
# (200, 201) inside whatever CIDR the VPC uses, so this works for any VPC.
#
# Examples:
#   VPC 172.31.0.0/16  → 172.31.200.0/24 and 172.31.201.0/24
#   VPC 10.0.0.0/16    → 10.0.200.0/24   and 10.0.201.0/24
#   VPC 192.168.0.0/16 → 192.168.200.0/24 and 192.168.201.0/24
#
# If those offsets clash with an existing subnet, increase subnet_offset below.

locals {
  # Number of additional bits needed to carve /24s from the VPC CIDR.
  # e.g. a /16 VPC needs 8 more bits  (16 + 8 = 24)
  #      a /20 VPC needs 4 more bits  (20 + 4 = 24)
  _vpc_prefix   = tonumber(split("/", data.aws_vpc.selected.cidr_block)[1])
  _subnet_bits  = 24 - local._vpc_prefix

  # Starting offset within the VPC's subnet space. 200 is high enough to
  # avoid conflicts with most default subnets (which start at 0, 1, 2…).
  _subnet_offset = var.subnet_offset

  # Final computed CIDRs — two subnets, one per AZ
  computed_subnet_cidrs = [
    for i in range(2) :
    cidrsubnet(data.aws_vpc.selected.cidr_block, local._subnet_bits, local._subnet_offset + i)
  ]
}

# ── Public subnets ───────────────────────────────────────────────────────────
resource "aws_subnet" "public" {
  count = var.create_subnets ? 2 : 0

  vpc_id                  = var.vpc_id
  cidr_block              = local.computed_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project}-public-${data.aws_availability_zones.available.names[count.index]}"
    Tier = "public"
  }
}

# ── Route table: 0.0.0.0/0 → IGW ────────────────────────────────────────────
resource "aws_route_table" "public" {
  count  = var.create_subnets ? 1 : 0
  vpc_id = var.vpc_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = data.aws_internet_gateway.existing[0].id
  }

  tags = {
    Name = "${var.project}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = var.create_subnets ? 2 : 0

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}
