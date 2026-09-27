"""mobcase: cross-platform (Android + iOS) mobile app testing toolkit.

Command entry points share a common ``mbc`` prefix (mbcinfo, mbcdev,
mbcstore, mbcrun, mbcpack, mbcexec) and are all backed by this package.

Core modules (imported by every command):
    mbc.ui         unified console output (this milestone)
    mbc.transport  push/pull/run/install over adb vs pymobiledevice3/ssh  (next)
    mbc.target     target resolution + device selection                   (next)
"""

__version__ = "0.1.0"