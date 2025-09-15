const {
  time,
  loadFixture,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("S3LogStorage", function () {
  let contract;
  let owner;
  
  beforeEach(async function () {
      [owner] = await ethers.getSigners();
      const S3LogStorage = await ethers.getContractFactory("S3LogStorage");
      contract = await S3LogStorage.deploy();
  });
  
  it("Should store and retrieve logs", async function () {
      await contract.storeLog("PUT", "blockchain", "test.json", "admin", "raw_data");
      
      expect(await contract.logCount()).to.equal(1);
      
      const log = await contract.getLog(0);
      expect(log.method).to.equal("PUT");
      expect(log.bucket).to.equal("blockchain");
      expect(log.key).to.equal("test.json");
      expect(log.akid).to.equal("admin");
  });
});