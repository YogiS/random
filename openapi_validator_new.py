import requests
from openapi_core.specs import loader
from openapi_core.validation.response.validators import ResponseValidator

def validate_api_endpoint(openapi_spec_path, endpoint_url):
    """
    Validates an API endpoint against an OpenAPI specification.

    Args:
        openapi_spec_path (str): Path to the OpenAPI specification file.
        endpoint_url (str): URL of the API endpoint to validate.

    Returns:
        bool: True if the endpoint is valid, False otherwise.
    """

    # Load the OpenAPI specification
    spec_dict = loader.load_from_file(openapi_spec_path)
    spec_obj = spec.Spec.from_dict(spec_dict)

    # Create a response validator
    response_validator = ResponseValidator(spec_obj)

    # Fetch the response from the endpoint
    response = requests.get(endpoint_url)

    # Validate the response against the OpenAPI specification
    validation_result = response_validator.validate(response)

    if validation_result.errors:
        print("Validation failed:")
        for error in validation_result.errors:
            print(f"  - {error}")
        return False
    else:
        print("Validation passed")
        return True

# Example usage
openapi_spec_path = "your_openapi_spec.yaml"
endpoint_url = "https://api.example.com/endpoint"

if validate_api_endpoint(openapi_spec_path, endpoint_url):
    print("Endpoint is valid against the OpenAPI specification.")
else:
    print("Endpoint is invalid against the OpenAPI specification.")
