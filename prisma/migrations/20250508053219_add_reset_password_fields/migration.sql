-- AlterTable
ALTER TABLE "User" ADD COLUMN "resetCode" TEXT;
ALTER TABLE "User" ADD COLUMN "resetCodeExpires" DATETIME;
