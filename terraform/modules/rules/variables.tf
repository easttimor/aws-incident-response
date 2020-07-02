variable "name" {
  description = "the resource name of the rule"
  type        = string
  default     = null
}

variable "description" {
  description = "the description of the rule"
  type        = string
  default     = null
}

variable "event_pattern" {
  description = "the event pattern described as a JSON object"
  type        = string
  default     = null
}

variable "is_enabled" {
  description = "whther the rule should be enabled"
  type        = bool
  default     = true
}

variable "sns_topic_arn" {
  description = "the Amazon resource name of the target SNS topic"
  type        = string
  default     = null
}