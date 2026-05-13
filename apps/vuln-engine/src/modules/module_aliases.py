# Re-export all modules for the module runner
from src.modules.remaining_modules import (
    FileUploadModule, OpenRedirectModule, CORSModule,
    APISecurityModule, DataExposureModule, MisconfigModule, CloudExposureModule,
)

# Provide clean imports
file_upload_module = FileUploadModule
redirect_module = OpenRedirectModule
cors_module = CORSModule
api_security_module = APISecurityModule
data_exposure_module = DataExposureModule
misconfig_module = MisconfigModule
cloud_module = CloudExposureModule
