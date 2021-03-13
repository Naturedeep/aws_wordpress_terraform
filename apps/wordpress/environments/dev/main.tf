# Define the provider
provider "aws" {
    region = var.region
}

## NETWORKING
# Create your vpc
resource "aws_vpc" "test_vpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "test_vpc"
  }
}

# Public subnet
resource "aws_subnet" "pub-subnet-1" {
  vpc_id     = aws_vpc.test_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = true
  depends_on= [aws_vpc.test_vpc]
  tags = {
    Name = "PUB_Subnet"
  }
}

# Private instances subnet
resource "aws_subnet" "prv-app-subnet-1" {
  vpc_id     = aws_vpc.test_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = false
  depends_on= [aws_vpc.test_vpc]
  tags = {
    Name = "APP_Subnet"
  }
}

# Private data subnet
resource "aws_subnet" "prv-data-subnet-1" {
  vpc_id     = aws_vpc.test_vpc.id
  cidr_block = "10.0.1.0/24"
  map_public_ip_on_launch = false
  depends_on= [aws_vpc.test_vpc]
  tags = {
    Name = "DATA_Subnet"
  }
}
#Define routing table
resource "aws_route_table" "wordpress_route-table" {
  vpc_id = aws_vpc.test_vpc.id

  /*route {
    cidr_block = "10.0.1.0/24"
    gateway_id = aws_internet_gateway.main.id
  }

  route {
    ipv6_cidr_block        = "::/0"
    egress_only_gateway_id = aws_egress_only_internet_gateway.foo.id
  }*/

  tags = {
    Name = "wordpress_Route_table"
  }
}

# Assicuate public subnet with routing table
resource "aws_route_table_association" "pub_subnet_route_association" {
  subnet_id      = aws_subnet.pub-subnet-1.id
  route_table_id = aws_route_table.wordpress_route-table.id
}

# Create internet gateway for servers to be connected to internet
resource "aws_internet_gateway" "wordpress_IG" {
  vpc_id = aws_vpc.test_vpc.id
  depends_on= [aws_vpc.test_vpc]
  tags = {
    Name = "wordpress_IGW"
  }
}
#Add default route in routing table to point to internet gateway
resource "aws_route" "default_route" {
  route_table_id              = aws_route_table.wordpress_route-table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id = aws_internet_gateway.wordpress_IG.id
}

resource "aws_lb" "lbWordpress" {
  name               = "lbWordpress"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.app_sg.id]
  subnets            = [aws_subnet.prv-app-subnet-1.id]

  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.lb_logs.bucket
    prefix  = "test-lb"
    enabled = true
  }

  tags = {
    Environment = "dev"
  }
}

# Create auto placement group and scaling group to scale instances

resource "aws_placement_group" "apgWordpress" {
  name     = "apgWordpress"
  strategy = "cluster"
}
resource "aws_launch_configuration" "alcWordpress" {
  name_prefix   = "alc_wordpress"
  image_id      = "ami-005c06c6de69aee84"
  instance_type = "t2.micro"

  lifecycle {
    create_before_destroy = true
  }
}
resource "aws_autoscaling_group" "bar" {
  name                      = "foobar3-terraform-test"
  max_size                  = 1
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 1
  force_delete              = true
  placement_group           = aws_placement_group.apgWordpress.id
  launch_configuration      = aws_launch_configuration.alcWordpress.name
  vpc_zone_identifier       = [aws_subnet.pub-subnet-1.id, aws_subnet.prv-app-subnet-1.id]

  tag {
    key                 = "foo"
    value               = "bar"
    propagate_at_launch = true
  }

  timeouts {
    delete = "15m"
  }

  tag {
    key                 = "lorem"
    value               = "ipsum"
    propagate_at_launch = false
  }
}

## SECURITY
# Create security group
resource "aws_security_group" "app_sg" {
  name        = "app_sg"
  description = "Allow Web inbound traffic"
  vpc_id      = aws_vpc.test_vpc.id

  ingress {
    description = "TLS from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "app_sg"
  }
}

## Storage
resource "aws_efs_file_system" "efsWordPress" {
  creation_token = "EFS for WordPress"
 
  tags = {
    Name = "EFS for WordPress"
  }
}

# Create a bucket to upload alb logs
resource "aws_s3_bucket" "lb_logs" {
  bucket = "lb_logs"
  acl = "public-read-write"
  tags = {
    Name = "lb_logs"
    Environment = "dev"
  }
}

resource "aws_db_subnet_group" "dbSubnetGroupWordpress" {
  name        = "db_subnet_group_wordpress"
  description = "Private subnets for RDS instance"
  subnet_ids  = [aws_subnet.prv-data-subnet-1.id]
}

# RDS DB instance
resource "aws_db_instance" "dbWordPress" {
    identifier = "dbwordpress"
    engine = "mysql"
    engine_version = "5.7"
    allocated_storage = var.allocated_storage
    instance_class = var.instance_class
    vpc_security_group_ids = ["aws_security_group.app_sg.id"]
    name = var.db_name
    username = var.db_admin
    password = var.db_password
    parameter_group_name = "default.mysql5.7"
    skip_final_snapshot = true
    db_subnet_group_name    = aws_db_subnet_group.dbSubnetGroupWordpress.id
    tags = {
        Name = "WordPress DB"
    }
}

## COMPUTE

# Create the instance with wordpress and php details
resource "aws_instance" "Web" {
  ami           = "ami-005c06c6de69aee84" # us-west-1
  instance_type = "t2.micro"
  tags = {
    Name = "Wordpress server 1"
  }
  count=1
  subnet_id = aws_subnet.prv-app-subnet-1.id
  key_name = "Web-key"
  security_groups = [ aws_security_group.app_sg.id ]
  ebs_block_device {
        device_name = "/dev/sdb"
        volume_size = var.volume_size
        delete_on_termination = "true"
    }
  # after connecting, running following commands on instance
   user_data = <<EOF
        #!/bin/bash
        echo "aws_efs_file_system.efsWordPress.dns_name}:/ /var/www/html nfs defaults,vers=4.1 0 0" >> /etc/fstab
        yum install -y php php-dom php-gd php-mysql
        for z in {0..120}; do
            echo -n .
            host "aws_efs_file_system.efsWordPress.dns_name}" && break
            sleep 1
        done
        cd /tmp
        wget https://www.wordpress.org/latest.tar.gz
        mount -a
        tar xzvf /tmp/latest.tar.gz --strip 1 -C /var/www/html
        rm /tmp/latest.tar.gz
        chown -R apache:apache /var/www/html
        systemctl enable httpd
        sed -i 's/#ServerName www.example.com:80/ServerName www.myblog.com:80/' /etc/httpd/conf/httpd.conf
        sed -i 's/ServerAdmin root@localhost/ServerAdmin admin@myblog.com/' /etc/httpd/conf/httpd.conf
        #setsebool -P httpd_can_network_connect 1
        #setsebool -P httpd_can_network_connect_db 1
        systemctl start httpd
        #firewall-cmd --zone=public --permanent --add-service=http
        #firewall-cmd --reload
        #iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        #iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    EOF
}
