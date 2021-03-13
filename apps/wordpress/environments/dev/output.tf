output "efs_dns_name" {
    value = "${aws_efs_file_system.efsWordPress.dns_name}"
}
 
output "ip_address" {
    value = aws_instance.Web.*.public_ip
}
 
output "sql_hostname" {
    value = "${aws_db_instance.dbWordPress.address}"
}
