#!/usr/bin/env python
# coding=utf-8
#
# Copyright © 2015-2016 VMware, Inc. All Rights Reserved.
#
# Licensed under the X11 (MIT) (the “License”) set forth below;
#
# you may not use this file except in compliance with the License. Unless required by applicable law or agreed to in
# writing, software distributed under the License is distributed on an “AS IS” BASIS, without warranties or conditions
# of any kind, EITHER EXPRESS OR IMPLIED. See the License for the specific language governing permissions and
# limitations under the License. Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
# Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# "THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.”

__author__ = 'yfauser'

import argparse
import library.nsx_logical_switch as lswitch
import library.nsx_dlr as dlr
import library.nsx_esg as esg
import library.nsx_usage as usage


def main():
    parser = argparse.ArgumentParser(description='PyNSXv Command Line Client for NSX for vSphere')
    parser.add_argument("-i",
                        "--ini",
                        help="nsx configuration file",
                        default="nsx.ini")
    parser.add_argument("-v",
                        "--verbose",
                        help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-d",
                        "--debug",
                        help="print low level debug of http transactions",
                        action="store_true")

    subparsers = parser.add_subparsers()
    lswitch.contruct_parser(subparsers)
    dlr.contruct_parser(subparsers)
    esg.contruct_parser(subparsers)
    usage.contruct_parser(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
