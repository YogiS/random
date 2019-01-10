#!/usr/bin/env python2.7
#name - file_archive
#input - source_dir, archive_dir, x_days, except, prefix
#description - provide a dir whose files need to be archived, archive dir where you need the zip archive file to be created
#provide a regex for files that you dont want to be archived, provide file older then a certain number of days that should be archived.
#after verifying the archive is created the files that were archived will be removed from the source dir

import os, sys, time, shutil, argparse, tempfile, fnmatch
import zipfile


def zipfiles(archive_list=[],zfilename='default.zip'):
  zout = zipfile.ZipFile(zfilename, "w", zipfile.ZIP_DEFLATED)
  for fname in archive_list:
  zout.write(fname)
  zout.close()

parser = argparse.ArgumentParser(prog=sys.argv[0])
parser.add_argument('--src', dest='source_dir', required=True, help='dir containing files to be compressed')
parser.add_argument('--dst', dest='archive_dir', required=True, help='destination where the compressed files will be moved')
parser.add_argument('--days', dest='days', type=int, default=14,help='files older then days specified will be compressed and archived')
parser.add_argument('--except', dest='re_except', nargs='*', default='',help='skip files that match this list of regex (seperated by spaces) ex: *.sql *.txt')
parser.add_argument('--prefix', dest='prefix', default='file_archive_',help='add prefix to temp file default .zip')

args=parser.parse_args()

#verify source_dir and archive_dir exists
if not os.path.exists(args.source_dir):
  print('directory ' + args.source_dir + ' does not exist')
if not os.path.exists(args.archive_dir):
  print('directory ' + args.archive_dir + ' does not exist, will attempt to create it')
  os.mkdir(args.archive_dir)
  if not os.path.exists(args.archive_dir):
    print('failed to create directory ' + args.archive_dir + ' exiting!')
    sys.exit(0)

time_now=time.time()

#read source_dira and create a file_list
file_list=list()

for f in os.listdir(args.source_dir):
  for pattern in args.re_except:
    if fnmatch.fnmatch(f,pattern):
      break
  else:
      f = os.path.join(args.source_dir, f)
      if os.stat(f).st_mtime < time_now - args.days * 86400:
        if os.access(f, os.R_OK):
          file_list.append(f)
        else:
          print 'skipping unreadable file: ' + f

#create archive file name
handle,archive_file_name=tempfile.mkstemp(suffix='.zip',prefix=args.prefix,dir=args.archive_dir,text=False)

#do the zip, verify the zip archive is created, remove files
if len(file_list) > 0:
  zipfiles(file_list,archive_file_name)
  if os.path.isfile(archive_file_name) and os.path.getsize(archive_file_name) > 0:
    for file in file_list:
      os.remove(file)
