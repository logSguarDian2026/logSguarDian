terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_lightsail_instance" "collector" {
  name              = "logsguardian-collector"
  availability_zone = "us-east-1a"
  blueprint_id      = "ubuntu_22_04"
  bundle_id         = "micro_3_0"
}

resource "aws_lightsail_instance_public_ports" "collector_ports" {
  instance_name = aws_lightsail_instance.collector.name

  port_info {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22
    cidrs     = ["200.119.177.59/32"]
  }
  port_info {
    protocol  = "tcp"
    from_port = 443
    to_port   = 443
    cidrs     = ["0.0.0.0/0"]
  }
  port_info {
    protocol  = "tcp"
    from_port = 80
    to_port   = 80
    cidrs     = ["0.0.0.0/0"]
  }
}

output "collector_public_ip" {
  value = aws_lightsail_instance.collector.public_ip_address
}

resource "aws_lightsail_instance" "clients" {
  name              = "logsguardian-clients"
  availability_zone = "us-east-1a"
  blueprint_id      = "ubuntu_22_04"
  bundle_id         = "medium_3_0"
}

resource "aws_lightsail_instance_public_ports" "clients_ports" {
  instance_name = aws_lightsail_instance.clients.name

  port_info {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22
    cidrs     = ["200.119.177.59/32"]
  }
  port_info {
    protocol  = "tcp"
    from_port = 3001
    to_port   = 3005
    cidrs     = ["200.119.177.59/32"]
  }
}

output "clients_public_ip" {
  value = aws_lightsail_instance.clients.public_ip_address
}
